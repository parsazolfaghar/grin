# Ronin — SP1: the engagement spine

Local-only multi-agent autonomous red-team orchestrator. SP1 is the fail-closed
authorization + scoped-execution spine: the sole path to executing any action.

## Install
```bash
pip install -e ".[dev]"        # add ",docker" for the docker runner
```

## Use
```bash
ronin engagement validate examples/acme-extnet.yaml
ronin run examples/acme-extnet.yaml      # submit: tool | command | target [| class]
ronin gate examples/acme-extnet.yaml     # approve/deny pending intrusive actions
ronin audit examples/acme-extnet.yaml    # print the evidence trail
```

Every action runs `resolve_class -> authorize -> gate -> execute -> audit`,
fail-closed. The spine sets the action class (anti-spoof); out-of-scope, excluded,
disallowed-class, out-of-window, and non-active-engagement actions are refused and
logged. See `docs/superpowers/specs/2026-06-13-engagement-spine-design.md`.

## Test
```bash
python3 -m pytest -v
```
