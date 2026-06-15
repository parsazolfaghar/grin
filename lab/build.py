"""Generate per-target uuid flags, write flag files into the build context, and render the
answer key. Run before `docker compose build`. Idempotent if --keep is passed and flags exist."""
import argparse
import sys
import uuid
from pathlib import Path

import yaml

LAB = Path(__file__).resolve().parent
GEN = LAB / "_generated"

# Static target metadata; only `flag` is generated per build.
TARGETS = [
    {"id": "t1-ssh", "container": "grin-lab-ssh", "ip": "172.30.0.11", "tier": "easy",
     "open_ports": [22], "vuln_class": "weak-credentials",
     "expected_findings": ["ssh weak credentials"], "win": "flag-in-loot", "_genfile": "t1.flag"},
    {"id": "t2-web", "container": "grin-lab-web", "ip": "172.30.0.12", "tier": "medium",
     "open_ports": [80], "vuln_class": "command-injection",
     "expected_findings": ["command injection"], "win": "flag-in-loot", "_genfile": "t2.flag"},
    {"id": "t3-chain", "container": "grin-lab-chain", "ip": "172.30.0.13", "tier": "hard",
     "open_ports": [80], "vuln_class": "privilege-escalation",
     "expected_findings": ["command injection", "sudo privilege escalation"],
     "win": "flag-in-loot", "_genfile": "t3.flag"},
]


def new_flags() -> dict:
    return {t["id"]: f"GRIN{{{uuid.uuid4().hex}}}" for t in TARGETS}


def render_answers(flags: dict, out_path: str) -> None:
    rows = []
    for t in TARGETS:
        row = {k: v for k, v in t.items() if not k.startswith("_")}
        row["flag"] = flags[t["id"]]
        rows.append(row)
    Path(out_path).write_text(yaml.safe_dump({"targets": rows}, sort_keys=False))


def write_flag_files(flags: dict) -> None:
    GEN.mkdir(exist_ok=True)
    for t in TARGETS:
        (GEN / t["_genfile"]).write_text(flags[t["id"]] + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Generate flag-lab flags + answer key")
    ap.add_argument("--keep", action="store_true",
                    help="reuse existing answers.yaml flags instead of regenerating")
    args = ap.parse_args(argv)
    answers = LAB / "answers.yaml"
    if args.keep and answers.exists():
        from grin.lab.answers import load_answers
        flags = {t.id: t.flag for t in load_answers(str(answers))}
    else:
        flags = new_flags()
    write_flag_files(flags)
    render_answers(flags, str(answers))
    print(f"wrote {answers} and {len(flags)} flag files under {GEN}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
