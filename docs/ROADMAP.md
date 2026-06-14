# Grin — Roadmap (future sub-projects)

Captured directions, not yet built. Each becomes its own brainstorm → spec → plan → build.
Charter reminder: Grin operates ONLY within an explicit, human-authorized engagement; the
fail-closed spine (scope/ROE/gate/audit) remains the sole execution path for everything below.

---

## R1 — Honeypot / trap detector ("smart") — PLANNED
**Goal:** before committing to exploitation, assess how likely a target/service is a decoy and
flag/de-prioritize it instead of charging in (don't waste an engagement or tip off defenders).

**Sketch:**
- A new Analyst "trap assessment" step that scores a target/service for honeypot likelihood from:
  - known honeypot fingerprints (Cowrie/Kippo SSH banners, Dionaea, Glastopf, Honeyd artifacts, T-Pot),
  - implausible signals (every port open, *too-easy* / uniform vulnerabilities, inconsistent OS
    fingerprints, canary-token / decoy-file bait, services that respond too perfectly),
- Emits a `suspected-honeypot` finding + lowers that target's priority in the Orchestrator's queue;
  the operator can override.
- LLM judgment + deterministic heuristics; reuses the Analyst, no new execution path.

## R2 — OPSEC / stealth layer ("anonymous", target-facing only) — PLANNED
**Goal:** minimize the footprint the blue team / honeypot observes, as realistic adversary emulation
*within* an authorized scope.

**Sketch:**
- Egress through the operator's authorized vantage (the bound `env` Kali/BlackArch box): VPN/SOCKS/
  proxy, source rotation.
- Scan **timing/jitter + rate-limiting** to stay under IDS thresholds; low-and-slow mode; non-default
  user agents / scan profiles.
- A per-engagement "stealth profile" the Orchestrator/Executor honor when proposing commands.

**Hard boundary (settled):** anonymity is **target-facing only**. The operator-side **audit trail stays
fully intact** — it proves the engagement stayed in scope/ROE and is the accountability record.
Anonymity in Grin = adversary emulation for an *authorized* engagement, NEVER a means to dodge
authorization or accountability or to act out of scope. The spine still authorizes + audits every action.

---

## R3 — Grin self-hardening ("secure") — DRAFT (awaiting operator's touches)
_Captured as a stub; the operator has additional requirements to add before this is specced._

**Initial sketch (to be refined):**
- Loot/secrets at rest: `0600` perms + opt-in encryption (age/agenix, already used on user); never
  log/echo secret values.
- Command-safety guard: deny/confirm destructive commands against the operator's own box
  (`rm -rf`, `mkfs`, `dd`, fork bombs); optional per-tool allow/deny lists.
- Keep existing properties: local-only models (no egress), fail-closed spine, append-only audit,
  hardened JSON parsing.

**STATUS: do not spec yet — pending the operator's added requirements ("the secure section needs touches").**

---

## R4 — Deployment mode toggle: single-machine ↔ split (app local / compute on rig) — PLANNED
**This is a baked-in, OPTIONAL app feature** — a first-class setting in the GUI (not hand-edited config).
The operator switches between two modes depending on where they're working:
- **Local mode** — app + inference (Ollama) + tools all on ONE machine (e.g. running everything on the
  rig itself, or a single powerful box).
- **Split mode** — app + Orchestrator/Analyst brain on the Mac; **GPU inference + Kali/BlackArch arsenal
  on the rig** (the current two-system setup).

**Design — a "backend profile" the app owns + persists:**
- A profile bundles `{ ollama_url, tool_env }`:
  - *Local*: `ollama_url = http://127.0.0.1:11434`, `tool_env = {kind: local|docker}`.
  - *Split (rig)*: `ollama_url = rig via SSH tunnel`, `tool_env = {kind: ssh, ssh_host: root@rig}`.
- The app exposes a **mode toggle / profile picker** (Local | Split, + custom), persists the choice, and
  applies it to engagements at launch — so the SAME app + SAME engagement runs either way with no YAML
  edits. An engagement may still override the env explicitly.
- Underlying primitive: the engine needs a **configurable Ollama endpoint** (see "still needed" below);
  the app's toggle just sets the active profile's `ollama_url` + `tool_env`.

**Already works today (the split-mode plumbing exists, just not toggled from the UI):**
- **Tool offload** — the engagement `env` binding already points tools at the rig:
  `env: {kind: ssh, ssh_host: "root@your-rig"}` (or docker into the rig's `grin-kali`/`grin-blackarch`).
  The ssh + docker runners are live-validated; the Mac drives, the rig runs the tools.
- **App on Mac** — the PyQt6 app is cross-platform; it already runs natively on macOS.

**Still needed (small):**
- **Inference offload** — `engage`/`execute` currently hardcode `OllamaClient()` (localhost). Add a
  configurable Ollama endpoint engine-wide (env var `GRIN_OLLAMA_URL` and/or a flag), so the Mac talks
  to the rig's Ollama. `bench` already has `--base-url`; generalize it to `_make_client`/
  `_make_executor_client`.
- **Secure transport (ties to R3)** — prefer an **SSH tunnel** (`ssh -L 11434:localhost:11434
  root@rig`) over exposing Ollama on the LAN (`OLLAMA_HOST=0.0.0.0`); then point Grin at
  `http://127.0.0.1:11434` which tunnels to the rig. Document both; recommend the tunnel.
- **Doctor (SP9) awareness** — `grin doctor` should check the *configured* (possibly remote) Ollama
  endpoint + rig reachability, not just localhost.

**Net:** once the configurable Ollama endpoint lands, `grin app` on the Mac + `GRIN_OLLAMA_URL`=rig
(via tunnel) + an `env: ssh→rig` engagement = full Mac-control / rig-compute split. Latency is fine
(GPU compute dominates, not LAN).

---

## R5 — Multi-arsenal env (Kali + BlackArch together) — OPTIONAL / LOW PRIORITY
**Decision (settled):** default stays **one arsenal per engagement** + lean on the env doctor (SP9) to
install missing tools on demand. Multi-arsenal is an optional power-user feature for the long tail only.

**Why the modest priority (honest):** Kali (~600 curated) and BlackArch (~2800+) **overlap heavily** on
the tools actually used (nmap, sqlmap, hydra, metasploit, nuclei, ffuf, gobuster…). Running a tool on
either distro is identical output — so combining them does **NOT** make any attack stronger. The only
gain is **breadth of available tooling** (the union, for niche tools that live on just one distro). And
SP9's permission-gated install already covers most "tool not present" cases on a single arsenal. True
dual-arsenal earns its keep only for a tool that exists on *one* distro and can't be installed on the
other — rare.

**If/when built:** the engagement `env` becomes a *set* of environments; a dispatcher routes each tool
command to the distro that has it (a tool→distro catalog, or "prefer Kali, fall back to BlackArch").
Cost: two containers resident + routing logic + version skew. Power gain: coverage, not strength.
