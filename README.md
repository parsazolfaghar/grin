# Grin

A multi-agent autonomous red-team orchestrator for **authorized** engagements. An LLM brain (cloud or
local) plans and drives offensive tools, but **every action is forced through a fail-closed spine** —
the sole path that resolves the action class, authorizes it against the engagement scope/ROE, gates it
by autonomy level, executes it on the bound arsenal, and appends an append-only audit record. The
orchestrator can go fully autonomous or pause for your approval; it never widens scope or runs an
out-of-scope/out-of-window action.

> Authorized engagements only. The operator-side audit trail is always intact — it is for
> accountability, never to dodge authorization or attribution.

## Quickstart — the desktop app (standalone)

Three things make a full Grin on one machine: the **app**, a **brain**, and an **arsenal**.

1. **Install / build the app** — see [Desktop app](#desktop-app). On macOS you get a clickable
   `Grin.app`.
2. **Brain** — put your cloud key in `~/.grin/env` (loaded at startup):
   ```
   GRIN_MODEL_BACKEND=openai
   GRIN_MODEL_URL=https://api.deepseek.com
   GRIN_MODEL_API_KEY=sk-...
   ```
   (Or run a local Ollama and leave these unset.)
3. **Arsenal** — install **Docker**; Grin provisions its own Kali/BlackArch tool containers
   (`grin arsenal up`), or auto-detects a local pentest host. See [Arsenal](#arsenal).

Then open the app, type a task or a target in the **Engage bar**, set the dashboard toggles, and go.

## Install (CLI / dev)
```bash
pip install -e ".[dev]"            # add ",docker" for the docker/arsenal runners, ",app" for the GUI
```

## The spine (authorization core)
```bash
grin engagement validate examples/acme-extnet.yaml
grin run examples/acme-extnet.yaml      # submit: tool | command | target [| class]
grin gate examples/acme-extnet.yaml     # approve/deny pending intrusive actions
grin audit examples/acme-extnet.yaml    # print the evidence trail
```
Every action runs `resolve_class → authorize → gate → execute → audit`, fail-closed. The spine sets
the action class (anti-spoof); out-of-scope, excluded, disallowed-class, out-of-window, and
non-active-engagement actions are refused and logged. There is no other code path that runs a command
or writes an allow line.

## The Executor

Run the AI agent on one objective (drives Kali/BlackArch tools through the spine):
```bash
grin execute examples/lab-recon.yaml --task "find web services" --target 10.0.0.5
grin execute --resume ./audit/home-lab-recon.<task-id>.journal.json   # after `grin gate`
```
The Executor asks the model for the next action, the spine authorizes/gates/runs it on the bound
arsenal, and the loop continues until the objective is met, the step budget runs out, or a gated
action needs `grin gate` approval (then `--resume`). **Evidence-gated findings:** a finding is only
reported if a real command actually ran in that task.

## The Orchestrator

Run a whole engagement from one high-level goal (adaptive, lead-chasing):
```bash
grin engage examples/external-net.yaml --goal "assess the external network"
grin engage examples/external-net.yaml --goal "find and verify web vulns" --seeds 10.0.0.5
```
The Orchestrator plans objectives, runs each through an Executor, an Analyst reads findings and
proposes follow-ups, and the loop runs until the goal is met or the objective budget
(`--max-objectives`, default 10) is hit. Gated (client) engagements pause intrusive objectives for
`grin gate` approval and report them at the end.

**Strength + stealth from the CLI** (also dashboard toggles / YAML fields):
```bash
grin engage examples/external-net.yaml --goal "..." --strength aggressive --stealth quiet
```
- `--strength recon|normal|aggressive|max` — recon (scan only, no exploit) → normal → aggressive
  (full ATT&CK sweep) → max (sweep + deeper budget).
- `--stealth off|quiet|paranoid` — applied at the spine: egress proxy/Tor, slow timing, rotated UA,
  and MAC/hostname spoof where it bites. See [Stealth](#stealth).

**Resuming a gated engagement:**
```bash
grin engage examples/external-net.yaml --goal "..."     # pauses intrusive objectives
grin gate examples/external-net.yaml                    # approve/deny
grin engage examples/external-net.yaml --resume         # continue the approved ones
```

**Per-role models** — route by objective type (`--recon-model`, `--exploit-model`,
`--planner-model`), each falling back to `--model`. The action-class tag drives model choice only; the
spine still authorizes every command.

## The Reporter
```bash
grin report examples/external-net.yaml -o report.md
```
Groups findings by severity (with evidence, the exact command, remediation), lists the methodology,
and appends an audit-trail + blocked-actions summary. The executive summary is deterministic, or a
short model narrative if a brain is up.

## Loot — captured secrets

Secrets the Executor obtains (credentials, keys, tokens, flags) are captured in full to
`audit/<engagement>.loot/` (`secrets.jsonl` + a readable `secrets.md`) and in the report's Secrets
section. No redaction — the point is concrete proof of exposure. Print with
`grin loot <engagement.yaml>`. (Loot holds live secrets in plaintext; handle as sensitive.
Everything stays local.)

## Model backends

Cloud-default when configured: set `GRIN_MODEL_BACKEND=openai`, `GRIN_MODEL_URL`, and
`GRIN_MODEL_API_KEY` to use any OpenAI-compatible endpoint (DeepSeek, Groq, OpenRouter, …). Absent →
local Ollama. An explicit `GRIN_MODEL_BACKEND` (ollama|openai) always wins. Client-mode engagements
warn and audit whenever a cloud backend is active.

## Arsenal

The offensive tools run in an **environment** bound to each engagement (`env.kind` in the YAML):
- `local` — tools on this host. `ssh` — a remote box. `docker` — a named container.
- `arsenal` — Grin's **self-provisioning** Kali + BlackArch containers (`grin arsenal up/down/status/add`)
  on any local Docker. A missing tool can be auto-installed or **asked for** (see the TOOLS toggle).
- `auto` — use local tools when running **on** a pentest host (Kali/Parrot/BlackArch, or the offensive
  tools are on PATH), else fall back to the Docker arsenal. App-launched engagements default to this,
  so the same task runs locally on a Kali laptop and in Docker on a Mac.

## Desktop app

`grin app` opens the native PyQt6 dashboard. Install it as a clickable, icon-bearing app:
- **macOS:** `scripts/build-macapp.sh` → `dist/Grin.app` (PyInstaller, unsigned). Drag to
  `/Applications`; first launch **right-click → Open** (Gatekeeper).
- **Linux:** `scripts/install-desktop.sh` installs a `.desktop` entry + icon (needs `grin` on PATH;
  NixOS is declarative).

A launcher-clicked app has no shell env — put cloud config in `~/.grin/env` (it never overrides a var
already set). The brain is cloud/local, the arsenal is Docker/host — neither is bundled into the app.

### Dashboard

- **Engage bar** — type a task (`bypass login page for www.test.com`) or a bare target
  (`www.test.com`); Grin parses the target + goal, shows the per-target menu of techniques/tools, and
  launches a scope-locked engagement. Typing the prompt is your authorization (recorded verbatim in
  the audit log).
- **MODE** — Cloud / Local / Split(rig): the brain + tool topology.
- **STRENGTH** — Recon / Normal / Aggressive / Max.
- **STEALTH** — Off / Quiet / Paranoid (see below).
- **TOOLS** — Ask / Auto / Never: when a run needs a tool not in the arsenal, Ask surfaces an
  Allow/Deny prompt (then installs on Allow), Auto installs on demand, Never fails.
- **Capture checkpoints** — in an aggressive run, each new flag pauses the sweep and asks: Keep
  sweeping / Focus this target / Next target / Stop.

## Stealth

Default-OFF, opt-in, target-facing only; every command is still audited as-run with the active level
recorded. Levels: `quiet` (egress + rotated UA + slower timing) and `paranoid` (+ nmap decoys, very
slow/low timing, MAC/hostname spoof where it bites — auto-skipped behind NAT). Source-IP egress uses
`GRIN_PROXY=socks5://…` or `GRIN_EGRESS=tor`; with neither set, egress is skipped and the doctor warns
(Grin never pretends you're hidden). Stealth only changes *how* an already-authorized command is
issued — never *what* is allowed.

## Doctor
```bash
grin doctor [engagement.yaml] [--fix] [--yes]
```
Preflight of Grin's runtime: engine deps, the model backend, arsenal containers, env reachability,
required tools, and the active stealth/egress posture. Read-only by default; `--fix` installs only
auto-fixable misses with per-item consent.

## Develop / test
```bash
ruff check grin/ tests/
QT_QPA_PLATFORM=offscreen pytest -q
```
CI runs ruff + the full suite on every push/PR (`.github/workflows/ci.yml`).
