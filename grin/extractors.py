"""Deterministic output extractors — parse known-tool stdout and return Secrets.

extract(tool, command, output, target) -> list[Secret]

Rules:
- Never raises on any input (including None).
- Returns [] when nothing matches or output is empty.
- Deduplicates by (label, value) before returning.
"""
import re
from typing import List

from grin.secret import Secret
from grin.finding import Finding, normalize_severity

# ---------------------------------------------------------------------------
# Hydra credential extractor
# ---------------------------------------------------------------------------
# Matches lines like:
#   [22][ssh] host: 172.30.0.11   login: admin   password: password
#   [80][http-post-form] host: 10.0.0.1\tlogin:  user1  password:  pass1
_HYDRA_RE = re.compile(r"login:\s*(\S+)\s+password:\s*(\S+)", re.IGNORECASE)


def _extract_hydra(command: str, output: str, target: str) -> List[Secret]:
    seen: set[tuple[str, str]] = set()
    results: List[Secret] = []
    for line in output.splitlines():
        for m in _HYDRA_RE.finditer(line):
            login = m.group(1).strip()
            password = m.group(2).strip()
            key = (login, password)
            if key in seen:
                continue
            seen.add(key)
            results.append(Secret(
                label="SSH credentials",
                value=f"{login}:{password}",
                target=target,
                tool="hydra",
                command=command,
                context="Extracted from hydra output",
            ))
    return results


# ---------------------------------------------------------------------------
# Flag extractor
# ---------------------------------------------------------------------------
_FLAG_RE = re.compile(r"GRIN\{[0-9a-fA-F]+\}", re.ASCII)


def _extract_flags(tool: str, command: str, output: str, target: str) -> List[Secret]:
    seen: set[str] = set()
    results: List[Secret] = []
    for m in _FLAG_RE.finditer(output):
        flag = m.group(0)
        if flag in seen:
            continue
        seen.add(flag)
        results.append(Secret(
            label="flag",
            value=flag,
            target=target,
            tool=tool,
            command=command,
            context="Captured flag",
        ))
    return results


# ---------------------------------------------------------------------------
# Private-key extractor
# ---------------------------------------------------------------------------
# Any PEM/OpenSSH private-key block exfiltrated into tool output. Capturing this is the T6 keystone:
# once the key is a recorded Secret, the orchestrator sees it (via replan) and plans crack->pivot
# instead of re-spawning the same "get a foothold" objective and re-stealing the same key.
_PRIVKEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


def _extract_private_keys(tool: str, command: str, output: str, target: str) -> List[Secret]:
    results: List[Secret] = []
    seen: set[str] = set()
    for m in _PRIVKEY_RE.finditer(output):
        block = m.group(0).strip()
        if block in seen:
            continue
        seen.add(block)
        results.append(Secret(
            label="private key",
            value=block,
            target=target,
            tool=tool,
            command=command,
            context="Private key exfiltrated from tool output",
        ))
    return results


# ---------------------------------------------------------------------------
# Cracked-password extractor (john/hashcat)
# ---------------------------------------------------------------------------
# john prints `<password>      (<source>)` on a line of its own when it cracks a hash. Capturing the
# plaintext lets the next objective actually use the key/credential — this was the missing piece when
# the T6 crack "ran" but its result was never recorded.
_JOHN_CRACK_RE = re.compile(r"^(\S+)\s+\(([^)]+)\)\s*$")
# `john --show` (and SSH-key cracks) print `<source>:<password>` where source is the key/hash file.
# Restricted to key/hash-looking sources so it doesn't swallow arbitrary colon-bearing output.
_JOHN_SHOW_RE = re.compile(r"(\S*(?:id_rsa|_rsa|\.hash|\.key|\.pem)\S*):(\S+)")


def _extract_cracked(tool: str, command: str, output: str, target: str) -> List[Secret]:
    results: List[Secret] = []
    seen: set[str] = set()
    for line in output.splitlines():
        m = _JOHN_CRACK_RE.match(line) or _JOHN_SHOW_RE.search(line)
        if not m:
            continue
        password = m.group(1).strip() if m.re is _JOHN_CRACK_RE else m.group(2).strip()
        source = m.group(2).strip() if m.re is _JOHN_CRACK_RE else m.group(1).strip()
        if password in seen:
            continue
        seen.add(password)
        results.append(Secret(
            label="cracked password",
            value=password,
            target=target,
            tool=tool,
            command=command,
            context=f"Cracked credential for {source}",
        ))
    return results


# ---------------------------------------------------------------------------
# Unix password-hash extractor
# ---------------------------------------------------------------------------
# A shadow/backup line bearing a crypt hash ($1$/$5$/$6$/$y$/$2[aby]$) — the T4 chain: read it, then
# crack it offline. Capturing it as a secret lets the orchestrator queue an offline-crack objective.
_HASH_RE = re.compile(r"([A-Za-z0-9_.-]+:\$(?:1|5|6|y|2[aby])\$[^\s:]+)")


def _extract_hashes(tool: str, command: str, output: str, target: str) -> List[Secret]:
    results: List[Secret] = []
    seen: set[str] = set()
    for m in _HASH_RE.finditer(output):
        h = m.group(1).strip()
        if h in seen:
            continue
        seen.add(h)
        results.append(Secret(
            label="password hash",
            value=h,
            target=target,
            tool=tool,
            command=command,
            context="Password hash for offline cracking",
        ))
    return results


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def extract(tool: str, command: str, output: str, target: str) -> List[Secret]:
    """Extract secrets from tool output deterministically.

    Runs all registered extractors and returns a deduplicated list of Secrets.
    Never raises — returns [] on any error or empty/None input.
    """
    try:
        out = output or ""
        cmd = command or ""
        tgt = target or ""
        tl = tool or ""

        if not out:
            return []

        creds = _extract_hydra(cmd, out, tgt)
        flags = _extract_flags(tl, cmd, out, tgt)
        keys = _extract_private_keys(tl, cmd, out, tgt)
        cracked = _extract_cracked(tl, cmd, out, tgt)
        hashes = _extract_hashes(tl, cmd, out, tgt)

        # Global dedup by (label, value) — in case two extractors somehow produce the same fact
        seen: set[tuple[str, str]] = set()
        combined: List[Secret] = []
        for sec in creds + flags + keys + cracked + hashes:
            key = (sec.label, sec.value)
            if key not in seen:
                seen.add(key)
                combined.append(sec)

        return combined
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Deterministic FINDINGS extractors (vulnerabilities, not secrets).
# nuclei is grin's broad real-world coverage tool: thousands of CVE/misconfig templates, and its
# output IS the evidence. Turn each hit into an evidence-backed Finding so coverage doesn't depend on
# the model remembering to report it.
# ---------------------------------------------------------------------------
# nuclei default line:  [template-id] [protocol] [severity] matched-at [optional name]
_NUCLEI_RE = re.compile(
    r"\[([^\]]+?)\]\s+\[(\w+)\]\s+\[(info|low|medium|high|critical|unknown)\]\s+(\S+)", re.I)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _extract_nuclei(command: str, output: str, target: str) -> List[Finding]:
    out: List[Finding] = []
    seen: set[str] = set()
    for line in _ANSI_RE.sub("", output or "").splitlines():   # strip color so titles parse clean
        m = _NUCLEI_RE.search(line)
        if not m:
            continue
        tid, proto, sev, matched = m.group(1).strip(), m.group(2), m.group(3), m.group(4)
        # strip a :variant suffix from the template id for a clean title, keep full id in evidence
        title = tid.split(":", 1)[0]
        if title in seen:
            continue
        seen.add(title)
        out.append(Finding(
            title=title,
            target=target,
            severity=normalize_severity(sev),
            evidence=f"nuclei [{tid}] [{proto}] matched at {matched}",
            tool="nuclei",
            command=command,
            recommendation="Triage the matched nuclei template and remediate the underlying issue.",
        ))
    return out


_BAC_HIT_RE = re.compile(r"^\s*HIT\s+(\S+)\s+(\d+)\s*(.*)$")


def _extract_bac_probe(command: str, output: str, target: str) -> List[Finding]:
    out: List[Finding] = []
    for line in (output or "").splitlines():
        m = _BAC_HIT_RE.match(line)
        if not m:
            continue
        path, status, reason = m.group(1), m.group(2), m.group(3).strip()
        out.append(Finding(
            title=f"Broken access control: {path} exposed without authentication",
            target=target,
            severity="medium",
            evidence=f"GET {path} -> {status} unauthenticated; {reason}".strip(),
            tool="bac-probe",
            command=command,
            recommendation="Require authentication/authorization for this resource.",
            vuln_class="broken-access-control",
            location=path,
        ))
    return out


_IDOR_RE = re.compile(r"^\s*IDOR\s+(\S+)\s+(\d+)\s*(.*)$")


def _extract_idor(command: str, output: str, target: str) -> List[Finding]:
    out: List[Finding] = []
    for line in (output or "").splitlines():
        m = _IDOR_RE.match(line)
        if not m:
            continue
        url, status, reason = m.group(1), m.group(2), m.group(3).strip()
        path = re.sub(r"^https?://[^/]+", "", url) or url
        out.append(Finding(
            title=f"IDOR: cross-user access to {path}",
            target=target,
            severity="high",
            evidence=f"GET {url} -> {status} returned another user's data; {reason}".strip(),
            tool="idor-probe",
            command=command,
            recommendation="Enforce object-level authorization: verify the resource belongs to "
                           "the authenticated caller.",
            vuln_class="idor",
            location=path,
        ))
    return out


_SQLI_RE = re.compile(r"^\s*SQLI\s+(\S+)\s+(.*)$")


def _extract_sqli(command: str, output: str, target: str) -> List[Finding]:
    out: List[Finding] = []
    for line in (output or "").splitlines():
        m = _SQLI_RE.match(line)
        if not m:
            continue
        url, rest = m.group(1), m.group(2).strip()
        path = re.sub(r"^https?://[^/]+", "", url) or url
        out.append(Finding(
            title=f"SQL injection authentication bypass at {path}",
            target=target,
            severity="critical",
            evidence=f"login at {url} bypassed with payload: {rest}",
            tool="sqli-probe",
            command=command,
            recommendation="Use parameterized queries / an ORM; never build SQL from user input.",
            vuln_class="sql-injection",
            location=path,
        ))
    return out


def extract_findings(tool: str, command: str, output: str, target: str) -> List[Finding]:
    """Deterministic vulnerability findings parsed from a known tool's output. Never raises; [] when
    nothing matches. Currently: nuclei, bac-probe, idor-probe, sqli-probe."""
    try:
        tl = (tool or "").lower()
        cl = (command or "").lower()
        if "nuclei" in tl or "nuclei" in cl:
            return _extract_nuclei(command or "", output or "", target or "")
        if "bac-probe" in tl or "bac-probe" in cl:
            return _extract_bac_probe(command or "", output or "", target or "")
        if "idor-probe" in tl or "idor-probe" in cl:
            return _extract_idor(command or "", output or "", target or "")
        if "sqli-probe" in tl or "sqli-probe" in cl:
            return _extract_sqli(command or "", output or "", target or "")
        return []
    except Exception:
        return []
