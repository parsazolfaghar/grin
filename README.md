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

## The Executor (SP2)

Run the AI agent on one objective (drives Kali/BlackArch tools through the spine):
```bash
ronin execute examples/lab-recon.yaml --task "find web services" --target 10.0.0.5
ronin execute --resume ./audit/home-lab-recon.<task-id>.journal.json   # after `ronin gate`
```
The Executor asks a local model (Ollama on the rig) for the next action, the spine
authorizes/gates/runs it on the bound Kali/BlackArch box, and the loop continues until the
objective is met, the step budget runs out, or a gated action needs `ronin gate` approval
(then `--resume`). Models are local-only; set the model with `--model` (default `qwen3:14b`).

## The Orchestrator (SP3)

Run a whole engagement from one high-level goal (adaptive, lead-chasing):
```bash
ronin engage examples/external-net.yaml --goal "assess the external network"
ronin engage examples/external-net.yaml --goal "find and verify web vulns" --seeds 10.0.0.5
```
The Orchestrator plans objectives, runs each through an SP2 Executor (which drives Kali/BlackArch
tools via the spine), an Analyst reads the findings and proposes follow-ups, and the loop runs
until the goal is met or the objective budget (`--max-objectives`, default 10) is hit. In a gated
(client) engagement, intrusive objectives pause for `ronin gate` approval and are reported at the
end. Models are local-only.

## Test
```bash
python3 -m pytest -v
```
