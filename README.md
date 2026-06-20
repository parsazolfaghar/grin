<div align="center">

<img src="grin/app/assets/logo.png" alt="GRIN" width="150">

# GRIN

**Autonomous red-team orchestrator.** It finds the foothold, escalates, pivots across hosts, and
captures the proof — *on its own*. Fail-closed by design.

[![ci](https://github.com/parsazolfaghar/grin/actions/workflows/ci.yml/badge.svg)](https://github.com/parsazolfaghar/grin/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.12+-0b18e8)
![license](https://img.shields.io/badge/license-all--rights--reserved-f3df33)
![status](https://img.shields.io/badge/use-authorized--only-red)

**⭐ Star it if grin is your kind of tool.**

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/parsazolfaghar/grin/main/scripts/install.sh | bash
```

> **Authorized security testing only.** You bring your own API key — grin ships with no API and
> **never proxies or sees your traffic**. What you do with it is your responsibility. Not open
> source: see [LICENSE](LICENSE).

---

## Why it actually lands

Most "AI hacks for you" demos stall the moment the model gets unlucky. Grin doesn't, because the
*model isn't the last mile* — code is.

- **Deterministic closers.** When the model would give up, grin's code takes over through the spine
  and finishes the job: default-cred sweep, command-injection, sudo & SUID privesc, LFI→crack, SQLi,
  and SSH-key lateral movement. The win isn't left to luck.
- **A brain that learns.** Persistent, cross-engagement memory recognizes the situation and applies
  the proven play every time — and learns from every success and wall.
- **Dual arsenal.** Self-provisioning **Kali + BlackArch** containers, complementary by design — a
  laptop with Docker is a full rig.
- **Fail-closed spine.** Every action: resolve → authorize → gate → execute → audit. Out-of-scope is
  *refused*, not run. The model can't go around it.
- **Broad coverage.** Integrated nuclei brings thousands of CVE/misconfig checks; every hit is an
  evidence-backed finding.
- **One-button updates.** One click pulls the code, re-deploys the in-container helpers, and syncs the
  brain — all three layers, current.

## Quickstart

1. **Install** — the one-liner above (Kali/Debian; needs `git` + `docker`). Or `pip install -e ".[app]"`.
2. **Bring your own brain** — drop a key in `~/.grin/deepseek.env` (any OpenAI-compatible endpoint;
   DeepSeek-V3 recommended), or run a local model with Ollama and skip the cloud entirely:
   ```
   GRIN_MODEL_BACKEND=openai
   GRIN_MODEL_URL=https://api.deepseek.com/v1
   GRIN_MODEL_API_KEY=sk-...        # YOUR key. grin never proxies it.
   ```
3. **Go** — launch the app, type a target + goal in the Engage bar, and watch it work. Or use the CLI
   below.

## Platforms

Runs on **macOS, Windows, and Linux**. The desktop app + engine are cross-platform Python; the
**arsenal runs anywhere Docker does**, so the same task works on a Kali laptop (native tools) and on a
Mac or Windows box (Docker Kali/BlackArch). The `curl | bash` one-liner targets Kali/Debian; on
macOS/Windows install with `pip install -e ".[app]"` + Docker Desktop.

## Full feature set

<details open>
<summary><b>Everything it does</b> — the actual machinery.</summary>

**Fail-closed spine**
- One execution path: resolve → authorize → gate → execute → audit (no other code runs a command)
- Scope + exclude enforcement — out-of-scope is *refused*
- Action classes: passive / active-scan / exploit / post-exploit; ROE time-window enforcement
- Append-only audit log of every allow & refuse; self-host destruction guard

**Autonomy & control**
- Modes: autonomous / action-gated / phase-gated
- Per-action approve/deny gating; pause & `--resume`
- Capture checkpoints on each new flag (aggressive); cooperative Stop mid-run
- Frictionless-within-authorization defaults (auto tool-install, no nag prompts)

**Multi-agent core**
- **Orchestrator** plans objectives, chases leads, replans · **Executor** per-objective observe→act loop
- **Analyst** reads findings & proposes follow-ups · **Medic** rescues stalls + records lessons · **Reporter** writes the deliverable

**Grin Brain (learning)**
- Persistent cross-engagement memory; detects the live situation and injects the proven play
- Playbooks (do) + pitfalls (avoid), reinforced by real outcomes; ships seeded; syncs new plays on update

**Deterministic closers** (the model-free last mile, all run through the spine)
- `cred-sweep` default/weak SSH creds · `web-rce` cmd-injection/SSTI RCE · `sudo-gtfo` sudo-NOPASSWD GTFOBins
- `suid-hijack` SUID PATH-hijack · `lfi-crack` traversal→offline-crack→SSH · `ssh-loot` SSH-key lateral movement

**Recon & exploitation**
- nmap · gobuster/ffuf fuzzing · **nuclei** (thousands of CVE/misconfig templates → evidence-backed findings)
- `web-scan` reflected-XSS discovery · sqlmap SQLi test/dump · subfinder/httpx external surface
- `grin-shell` drives interactive tools (msfconsole/meterpreter/ssh) · john + rockyou offline cracking

**Arsenal & environments**
- Self-provisioning **Kali + BlackArch** containers, complementary tool split across both distros
- Auto-install missing tools (ask/auto/never) · envs: local / ssh / docker / arsenal / auto · a laptop with Docker = a full rig

**Brains & models**
- Any OpenAI-compatible cloud (DeepSeek/Groq/OpenRouter) or local Ollama
- Per-role model routing (planner/recon/exploit) · cloud→cloud fallback tiers · **BYO key, never proxied**

**Strength & stealth**
- Strength: recon / normal / aggressive (full ATT&CK sweep) / max
- Stealth: off / quiet / paranoid — egress proxy/Tor, slow timing, UA rotation, MAC/hostname spoof where it bites

**Output & evidence**
- Reports: **Markdown / SARIF / HTML** · full loot capture (creds, keys, flags) · evidence-gated findings
- ATT&CK coverage mapping · deterministic "discoveries" view · **CI mode** (`grin ci`, fail a build on findings ≥ severity)

**Desktop app & workflow**
- Natural-language Engage bar (target+goal → scope-locked run) · MODE/STRENGTH/STEALTH/TOOLS toggles
- Live findings/loot/audit/discoveries · approve/deny actions + tool installs · Export Report button
- Engagement playbooks: recon-only / external-asm / internal-network / bug-bounty / ctf-solver

**Platform & ops**
- macOS · Windows · Linux · one-button complete update (code + helpers + brain) · `grin doctor` preflight
- `grin --version` + CHANGELOG · full CLI (engage/ci/report/loot/arsenal/brain/doctor/lab/labbench/…) · built-in graded lab + benchmark

</details>

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
