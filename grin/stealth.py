"""Built-in stealth layer: turn an engagement's stealth level into command transforms (egress proxy,
scan timing, fingerprint) applied at the spine chokepoint, plus device-spoof setup builders. Pure +
default-OFF: an 'off' profile is an identity transform. Never raises. Target-facing only; the audit
records the as-run command and the active level, so the operator trail stays truthful."""
import re
from dataclasses import dataclass

STEALTH_LEVELS = ("off", "quiet", "paranoid")

# interface names are interpolated into a shell command — only allow real iface charset (defense in
# depth; today the sole caller passes a hardcoded "eth0", but never trust a future caller)
_IFACE_RE = re.compile(r"[A-Za-z0-9:._-]+")

# tools whose traffic actually leaves the host — only these get egress/fingerprint treatment
NETWORK_TOOLS = ("nmap", "curl", "wget", "nikto", "hydra", "sqlmap", "gobuster", "ffuf")
# a believable, non-default browser UA (deterministic for tests; rotation is a later refinement)
DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
# a small pool of believable desktop browser UAs; one is picked per run (stable within a run,
# varying across runs) so a fixed UA never becomes a cross-engagement tell. Refresh periodically —
# a UA that names an old browser version is itself a fingerprint.
UA_POOL = (
    DEFAULT_UA,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0.0.0 Safari/537.36",
)


def _pick_ua(seed) -> str:
    """Deterministically choose a UA from the pool for this run. A stable seed (the engagement id)
    keeps the UA constant within a run but different across engagements. No seed -> DEFAULT_UA."""
    if not seed:
        return DEFAULT_UA
    import hashlib
    idx = int(hashlib.sha1(str(seed).encode()).hexdigest(), 16) % len(UA_POOL)
    return UA_POOL[idx]


@dataclass(frozen=True)
class StealthProfile:
    level: str
    egress: str = ""        # "" | socks5://host:port
    timing: str = ""        # nmap timing flags, e.g. "-T2" or "-T1 --scan-delay 1s --max-rate 50"
    decoys: bool = False
    ua: str = ""
    device: bool = False


def _resolve_egress(env) -> str:
    proxy = (env.get("GRIN_PROXY") or "").strip()
    if proxy:
        return proxy
    if (env.get("GRIN_EGRESS") or "").strip().lower() == "tor":
        return "socks5://127.0.0.1:9050"
    return ""


def profile_for(level: str, env, seed=None) -> StealthProfile:
    level = level if level in STEALTH_LEVELS else "off"
    if level == "off":
        return StealthProfile(level="off")
    egress = _resolve_egress(env)
    ua = _pick_ua(seed)   # per-run UA (stable within a run); DEFAULT_UA when no seed
    if level == "quiet":
        return StealthProfile(level="quiet", egress=egress, timing="-T2", decoys=False,
                              ua=ua, device=False)
    return StealthProfile(level="paranoid", egress=egress,
                          timing="-T1 --scan-delay 1s --max-rate 50", decoys=True,
                          ua=ua, device=True)


def apply(profile: StealthProfile, tool: str, command: str) -> str:
    """Rewrite an already-authorized command per the profile. Identity when level is off. Idempotent —
    never double-injects a flag already present."""
    if profile.level == "off":
        return command
    cmd = command
    is_net = tool in NETWORK_TOOLS
    if tool == "nmap":
        if profile.timing and "-T" not in cmd:
            cmd = cmd.replace("nmap", "nmap " + profile.timing, 1)
        if profile.decoys and "-D " not in cmd:
            cmd = cmd + " -D RND:5"
    if tool == "curl" and profile.ua and "-A " not in cmd and "--user-agent" not in cmd:
        cmd = cmd + f' -A "{profile.ua}"'
    if tool == "nikto" and profile.ua and "-useragent" not in cmd:
        cmd = cmd + f' -useragent "{profile.ua}"'
    if profile.egress and is_net and "proxychains" not in cmd:
        cmd = f"proxychains -q {cmd}"
    return cmd


def can_spoof_device(host_has_arsenal_fn, which) -> bool:
    """Device (MAC/hostname) spoofing only bites on a LOCAL pentest host with macchanger present.
    Behind NAT (Docker-on-Mac) host_has_arsenal_fn() is False -> skip (it would be cosmetic)."""
    try:
        return bool(host_has_arsenal_fn()) and bool(which("macchanger"))
    except Exception:  # noqa: BLE001 - detection never raises
        return False


def device_setup(profile: StealthProfile, *, iface: str, can_spoof: bool) -> list:
    """Commands to spoof the bound interface's identity at engagement start. Empty unless the profile
    enables device spoofing AND the host can actually do it."""
    if not (profile.device and can_spoof):
        return []
    if not _IFACE_RE.fullmatch(iface or ""):
        raise ValueError(f"refusing to spoof unsafe interface name {iface!r}")
    return [f"macchanger -r {iface}",
            "hostnamectl set-hostname localhost"]
