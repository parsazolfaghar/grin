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

## R4 — Control plane (Mac) / compute plane (rig) — PLANNED (partly already works)
**Goal:** the app + engine **run on the Mac** (the daily machine), but offload the heavy lifting to the
rig: **GPU inference** (Ollama on the RTX 3060) and the **Kali/BlackArch arsenal**. Mac = UI +
Orchestrator/Analyst brain; rig = compute + tool execution.

**Already works today:**
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
