"""Grin Brain — persistent, cross-engagement learning.

The Executor has no memory: each run starts cold, so the model re-makes the same mistakes (wandering
into re-scans on a permission-denied flag; brute-forcing root instead of using a stolen key; declaring
'done' without the flag) and re-discovers the same wins by luck — which is why a fresh-flag round lands
a *moving* 4/6 instead of a consistent 6/6.

The Brain fixes that. It stores LESSONS keyed by SITUATION (a tag detected from the live run, e.g.
'root-owned-flag', 'stolen-ssh-key'). Each lesson is a 'playbook' (do this) or a 'pitfall' (avoid
this) with a worked/failed tally that reinforces over time. At each step the Executor detects the
current situations, pulls the matching lessons, and injects them into the prompt — so the proven play
is applied EVERY time, not rediscovered. The Medic writes lessons from real outcomes, so grin learns
from everything right and wrong it has ever done.

Pure store + retrieval + situation detection (unit-tested); the only I/O is the JSONL file."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime


def default_path() -> str:
    return os.path.expanduser(os.environ.get("GRIN_BRAIN_PATH", "~/.grin/brain/lessons.jsonl"))


# Proven plays, seeded so grin starts smart and then reinforces from real outcomes. Each is what
# closed a target deterministically in testing; the situation tags match detect_situations().
DEFAULT_SEEDS = [
    ("cmdi-foothold", "playbook",
     "You have command execution. Run commands through it with web-rce: "
     "`web-rce --url <foothold-url> --param <param> --method POST --mode cmdi --cmd '<cmd>'`. "
     "Read the flag; if it's permission-denied/root-owned, ESCALATE (see root-owned-flag)."),
    ("root-owned-flag", "playbook",
     "Permission denied on a target/sensitive file means ESCALATE, not re-scan. Enumerate BOTH privesc "
     "classes, then use the matching deterministic helper (try both — they don't conflict): "
     "(1) sudo-NOPASSWD: `sudo-gtfo --url <foothold-url> --param <param> --method POST --mode <cmdi|ssti> "
     "--flag <target-file>` (runs `sudo -l` + GTFOBins). "
     "(2) SUID PATH-hijack: if a SUID-root binary calls another program by bare name, "
     "`suid-hijack --url <foothold-url> --param <param> --mode <cmdi|ssti> --flag <target-file>`. "
     "target-file e.g. /root/flag.txt (CTF) or any protected file (real work). Do NOT re-enumerate the "
     "web app or declare done — run BOTH helpers before giving up on privesc."),
    ("ssti-foothold", "playbook",
     "SSTI/template-injection foothold (param renders e.g. {{7*7}} -> 49). Get RCE with "
     "`web-rce --url <url> --param <param> --mode ssti --cmd '<cmd>'`. If the flag is root-owned and a "
     "SUID-root binary calls a program by bare name, escalate with "
     "`suid-hijack --url <url> --param <param> --mode ssti --flag /root/flag.txt`. Do NOT declare done "
     "before running suid-hijack."),
    ("stolen-ssh-key", "playbook",
     "You have an SSH key (auto-saved to /tmp/loot/id_rsa). The MOMENT you also know another in-scope "
     "host (from `nmap -sn <range>`), pivot with ssh-loot: "
     "`ssh-loot --host <discovered-host> --key /tmp/loot/id_rsa --readme '<README/clue text>'` — it "
     "cracks the passphrase and logs in as the right account. Do NOT brute root or run nmap NSE."),
    ("flag-not-captured", "pitfall",
     "Do NOT declare the objective done/complete until you have CONCRETE PROOF — the actual sensitive "
     "file contents, a confirmed shell, or a captured credential (a CTF GRIN{...} flag is one example "
     "of proof). A foothold is not proof — keep escalating or pivoting until you have it."),
]


@dataclass
class Lesson:
    situation: str
    text: str
    kind: str = "playbook"      # "playbook" (do this) | "pitfall" (avoid this)
    worked: int = 0
    failed: int = 0
    ts: str = ""

    @property
    def score(self) -> int:
        return self.worked - self.failed


class Brain:
    """A JSONL-backed lessons store. Dedup key = (situation, text); record() upserts + tallies."""

    def __init__(self, path: str | None = None):
        self.path = path or default_path()
        self._lessons: dict[tuple, Lesson] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    d = json.loads(line)
                    le = Lesson(situation=d["situation"], text=d["text"],
                                kind=d.get("kind", "playbook"),
                                worked=int(d.get("worked", 0)), failed=int(d.get("failed", 0)),
                                ts=d.get("ts", ""))
                    self._lessons[(le.situation, le.text)] = le
        except (OSError, json.JSONDecodeError, KeyError):
            pass

    def _save(self) -> None:
        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(self.path, "w") as f:
            for le in self._lessons.values():
                f.write(json.dumps(asdict(le)) + "\n")

    def record(self, situation: str, text: str, *, kind: str = "playbook",
               outcome: str = "worked") -> None:
        """Add or reinforce a lesson. outcome in {'worked','failed'} bumps the tally."""
        key = (situation, text)
        le = self._lessons.get(key) or Lesson(situation=situation, text=text, kind=kind)
        le.kind = kind
        if outcome == "worked":
            le.worked += 1
        elif outcome == "failed":
            le.failed += 1
        le.ts = datetime.now().isoformat(timespec="seconds")
        self._lessons[key] = le
        self._save()

    def ensure_seeded(self) -> None:
        """Populate the proven plays once, if the brain is empty. Makes grin consistent out of the
        box; real outcomes then reinforce/extend these."""
        if self._lessons:
            return
        for situation, kind, text in DEFAULT_SEEDS:
            self.record(situation, text, kind=kind, outcome="worked")

    def lessons_for(self, situations: list[str]) -> list[Lesson]:
        """Lessons matching any current situation: playbooks first (by net score desc), then pitfalls
        (by times-failed desc)."""
        want = set(situations or [])
        hits = [le for le in self._lessons.values() if le.situation in want]
        plays = sorted([x for x in hits if x.kind == "playbook"],
                       key=lambda x: (-x.score, -x.worked))
        pits = sorted([x for x in hits if x.kind != "playbook"], key=lambda x: -x.failed)
        return plays + pits

    def render(self, situations: list[str], *, limit: int = 10) -> str:
        """A prompt block of the relevant learned lessons, or '' if none match."""
        hits = self.lessons_for(situations)[:limit]
        if not hits:
            return ""
        plays = [le for le in hits if le.kind == "playbook"]
        pits = [le for le in hits if le.kind != "playbook"]
        lines = ["## What grin has LEARNED applies right now (highest priority — follow these)"]
        for le in plays:
            lines.append(f"- DO: {le.text}")
        for le in pits:
            lines.append(f"- AVOID: {le.text}")
        return "\n".join(lines) + "\n\n"


# ---------------------------------------------------------------------------
# Situation detection — pure: read the run's history text, emit the tags that lessons key on.
# ---------------------------------------------------------------------------

_SEED_BY_SITUATION: dict[str, list[tuple]] = {}
for _s, _k, _t in DEFAULT_SEEDS:
    _SEED_BY_SITUATION.setdefault(_s, []).append((_k, _t))


def reinforce_success(brain: "Brain", history: str, target: str = "") -> None:
    """A flag was captured: bump the 'worked' tally of the proven plays whose situation was active in
    this run, so the plays that win get stronger over time. Never raises."""
    try:
        for sit in detect_situations(history, target=target):
            for kind, text in _SEED_BY_SITUATION.get(sit, []):
                if kind == "playbook":
                    brain.record(sit, text, kind="playbook", outcome="worked")
    except Exception:  # noqa: BLE001
        pass


def learn_failure(brain: "Brain", situation: str, lesson: str) -> None:
    """The Medic records a pitfall (what went wrong + the corrective play) from a real wall, so grin
    stops repeating it. Never raises."""
    try:
        brain.record(situation, lesson, kind="pitfall", outcome="failed")
    except Exception:  # noqa: BLE001
        pass


def detect_situations(history: str, *, target: str = "") -> list[str]:
    h = history or ""
    low = h.lower()
    sits: list[str] = []

    def add(t):
        if t not in sits:
            sits.append(t)

    if "permission denied" in low or ("/root/flag" in low and "cannot open" in low):
        add("root-owned-flag")           # generic: hit a permission wall -> escalate
    if "begin openssh private key" in low or "begin rsa private key" in low:
        add("stolen-ssh-key")
    # SSTI confirmed: a {{7*7}}-style probe reflected as 49, an ssti mention, or web-rce --mode ssti
    if ("{{7*7}}" in h or "{{ 7*7 }}" in h or "ssti" in low or "--mode ssti" in low
            or "jinja" in low or "{{" in h):
        add("ssti-foothold")
    if "uid=" in low and ("web-rce" in low or "ping" in low or "?host=" in low or "cmd" in low):
        add("cmdi-foothold")
    # "unproven": only nag once a foothold exists but no concrete proof yet (a CTF flag is one proof
    # form). Avoids firing on step 1 before there's anything to prove; general to real engagements.
    foothold = bool(sits)
    has_proof = "grin{" in low or "uid=0(root)" in low
    if foothold and not has_proof:
        add("flag-not-captured")
    return sits
