# Grin — SP1: the engagement spine

Local-only multi-agent autonomous red-team orchestrator. SP1 is the fail-closed
authorization + scoped-execution spine: the sole path to executing any action.

## Install
```bash
pip install -e ".[dev]"        # add ",docker" for the docker runner
```

## Use
```bash
grin engagement validate examples/acme-extnet.yaml
grin run examples/acme-extnet.yaml      # submit: tool | command | target [| class]
grin gate examples/acme-extnet.yaml     # approve/deny pending intrusive actions
grin audit examples/acme-extnet.yaml    # print the evidence trail
```

Every action runs `resolve_class -> authorize -> gate -> execute -> audit`,
fail-closed. The spine sets the action class (anti-spoof); out-of-scope, excluded,
disallowed-class, out-of-window, and non-active-engagement actions are refused and
logged. See `docs/superpowers/specs/2026-06-13-engagement-spine-design.md`.

## The Executor (SP2)

Run the AI agent on one objective (drives Kali/BlackArch tools through the spine):
```bash
grin execute examples/lab-recon.yaml --task "find web services" --target 10.0.0.5
grin execute --resume ./audit/home-lab-recon.<task-id>.journal.json   # after `grin gate`
```
The Executor asks a local model (Ollama on the rig) for the next action, the spine
authorizes/gates/runs it on the bound Kali/BlackArch box, and the loop continues until the
objective is met, the step budget runs out, or a gated action needs `grin gate` approval
(then `--resume`). Models are local-only; set the model with `--model` (default `qwen3:14b`).

### Evidence-gated findings (SP7)

The Executor will not report findings unless at least one tool actually ran in that task. If the
model tries to declare findings with no command executed, it's rejected and re-prompted to gather
evidence first — so every reported finding is backed by a real command + output (and a task that
runs nothing simply reports no findings).

## The Orchestrator (SP3)

Run a whole engagement from one high-level goal (adaptive, lead-chasing):
```bash
grin engage examples/external-net.yaml --goal "assess the external network"
grin engage examples/external-net.yaml --goal "find and verify web vulns" --seeds 10.0.0.5
```
The Orchestrator plans objectives, runs each through an SP2 Executor (which drives Kali/BlackArch
tools via the spine), an Analyst reads the findings and proposes follow-ups, and the loop runs
until the goal is met or the objective budget (`--max-objectives`, default 10) is hit. In a gated
(client) engagement, intrusive objectives pause for `grin gate` approval and are reported at the
end. Models are local-only.

### Resuming a gated engagement (SP5)

For client (gated) engagements, intrusive objectives pause for approval. Approve, then resume:
```bash
grin engage examples/external-net.yaml --goal "assess the external network"   # pauses intrusive objectives
grin gate examples/external-net.yaml                                          # approve/deny
grin engage examples/external-net.yaml --resume                               # continue the approved ones
grin report examples/external-net.yaml -o report.md
```
`--resume` resumes every approved blocked objective (detected via the results store), merges their
findings, keeps the adaptive loop going, and re-saves the result. Denied / not-yet-approved
objectives stay blocked; if nothing is approved yet it reports "nothing to resume."

### Per-role models (SP6)

Route models by objective type (all local Ollama; default is one `--model` for everything):
```bash
grin engage examples/external-net.yaml --goal "assess the external network" \
  --recon-model qwen3:8b --exploit-model hermes3:8b --planner-model qwen3:14b
```
Recon/passive objectives run on `--recon-model`, exploit/post-exploit objectives on
`--exploit-model`, planning on `--planner-model` — each falling back to `--model`. The action-class
tag drives model choice only; the spine still resolves and authorizes every command.

## The Reporter (SP4)

Turn a finished engagement into a Markdown report:
```bash
grin engage examples/external-net.yaml --goal "assess the external network"   # saves the result
grin report examples/external-net.yaml -o report.md                            # renders it
```
The report groups findings by severity (with evidence, the exact command, and remediation), lists
the methodology the Orchestrator followed, and appends an audit-trail + blocked-actions summary.
The executive summary is deterministic by default; if a local model is up it writes a short
narrative instead (and falls back to deterministic if the model is unavailable).

## Test
```bash
python3 -m pytest -v
```
