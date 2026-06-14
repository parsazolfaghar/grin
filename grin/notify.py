"""Phone notifications (roadmap R7) via ntfy — opt-in, self-hostable.

Set GRIN_NTFY_URL to a full ntfy topic URL (e.g. http://your-rig:8080/grin or https://ntfy.sh/grin-<rand>).
Self-host ntfy on the rig/LAN so nothing leaves operator control. First cut is NOTIFY-ONLY (approve at
the console / `grin gate`); actionable approve/deny from the phone needs a callback listener (deferred).
Fail-soft: a notification never blocks or breaks an engagement.
"""
import os

import httpx


def ntfy_url() -> str | None:
    return os.environ.get("GRIN_NTFY_URL") or None


def ntfy_send(url: str, title: str, message: str, timeout: float = 5.0) -> bool:
    """POST a message to an ntfy topic. Returns True on success, False on any failure (fail-soft)."""
    try:
        httpx.post(url, content=(message or "").encode("utf-8"),
                   headers={"Title": title, "Priority": "high", "Tags": "rotating_light"},
                   timeout=timeout)
        return True
    except Exception:  # noqa: BLE001
        return False
