# Grin — Roadmap (future sub-projects)

Captured directions, not yet built. Each becomes its own brainstorm → spec → plan → build.
Charter reminder: Grin operates ONLY within an explicit, human-authorized engagement; the
fail-closed spine (scope/ROE/gate/audit) remains the sole execution path for everything below.

## Guiding principle (NON-NEGOTIABLE): none of these may reduce Grin's offensive strength
Every item here is **ADDITIVE and OPT-IN / OVERRIDE-ABLE**. None of them may cap, throttle, or censor
Grin's offensive capability against an authorized target. Concretely, when implemented each MUST:
- be **advisory** (informs/flags) or **opt-in** (a mode the operator turns on) — never a default that
  weakens output;
- always offer an **operator override** (full power on demand);
- protect the **operator/tool**, not shield the **target**.

The ONLY hard limit on Grin is the charter boundary — **authorized scope + ROE + audit** — which is the
license to operate, not a capability limit. Within that boundary, full strength is the default. A
"safety" feature that quietly makes Grin weaker against an in-scope target is a BUG, not a feature.

---

## R1 — Honeypot / trap detector ("smart") — BUILT (advisory); only live tuning remains
**Built (2026-06-14):** `grin/honeypot.py` `assess(findings, audit_lines)` (deterministic fingerprint +
implausibility scorer); `grin honeypot <eng>` advisory CLI; AND **loop-integrated** — the Orchestrator
calls `_flag_honeypot(findings)` after each objective and appends ONE advisory `Suspected honeypot/decoy`
info finding when signals fire. **Strictly advisory:** it never blocks, removes objectives, or gates
execution (tested: emits the finding AND the engagement still completes; idempotent; silent when clean).
**Remaining (needs the rig + real honeypot traffic):** threshold/fingerprint-catalog tuning and (optional)
de-prioritizing a flagged target in the queue. De-prioritization deferred precisely because it edges
toward "limiting" — must stay override-able per the guiding principle.

**Goal:** before committing to exploitation, assess how likely a target/service is a decoy and
flag/de-prioritize it instead of charging in (don't waste an engagement or tip off defenders).

**Sketch:**
- A new Analyst "trap assessment" step that scores a target/service for honeypot likelihood from:
  - known honeypot fingerprints (Cowrie/Kippo SSH banners, Dionaea, Glastopf, Honeyd artifacts, T-Pot),
  - implausible signals (every port open, *too-easy* / uniform vulnerabilities, inconsistent OS
    fingerprints, canary-token / decoy-file bait, services that respond too perfectly),
- Emits a `suspected-honeypot` finding + lowers that target's priority in the Orchestrator's queue.
- **ADVISORY ONLY — never blocks.** Grin can still fully engage a suspected honeypot if the operator
  chooses; the flag informs, it does not gate or remove capability. Default behavior unchanged.
- LLM judgment + deterministic heuristics; reuses the Analyst, no new execution path.

## R2 — OPSEC / stealth layer ("anonymous", target-facing only) — DEFERRED to an at-rig session
**Deliberately held (2026-06-14):** unlike R1/R4, R2's first cut threads a stealth profile through the
Executor/prompts and its knob values (timing thresholds, IDS-evading flags) only become meaningful when
tuned against live targets on the rig — so building it remotely/blind risks rework. Resume when at the
machine. (Opt-in / default-OFF per the guiding principle still applies.)

**In R2 scope — DEVICE/IDENTITY SPOOFING (target-facing only):** Grin does NOT spoof the host device
today. Add (opt-in, on the bound vantage box): MAC-address spoofing (macchanger), hostname, source IP via
VPN/SOCKS/proxy egress, scan-fingerprint/UA profiles. Hides the *attacker vantage* from the target/blue
team. Boundary unchanged: target-facing only — the operator-side audit trail stays intact (accountability),
authorized-engagement only, never to dodge authorization/attribution by law enforcement.
**Goal:** minimize the footprint the blue team / honeypot observes, as realistic adversary emulation
*within* an authorized scope.

**Sketch:**
- Egress through the operator's authorized vantage (the bound `env` Kali/BlackArch box): VPN/SOCKS/
  proxy, source rotation.
- Scan **timing/jitter + rate-limiting** to stay under IDS thresholds; low-and-slow mode; non-default
  user agents / scan profiles.
- A per-engagement "stealth profile" the Orchestrator/Executor honor when proposing commands.
- **OPT-IN ONLY — default is full-speed / full-power, loud.** Stealth is a mode the operator enables;
  it never silently throttles or limits the toolset. Loud-and-fast remains a first-class option.

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
- Command-safety guard: **self-protection ONLY** — deny/confirm commands that would destroy the
  OPERATOR's own box / runner host (`rm -rf /`, `mkfs`, `dd` on the host disk, fork bombs). It MUST NOT
  censor or weaken legitimate offensive commands against an authorized **target** (that would violate
  the guiding principle). Always operator-override-able; default does not touch offensive tooling.
- Keep existing properties: local-only models (no egress), fail-closed spine, append-only audit,
  hardened JSON parsing.

**SAFE DEFAULTS BUILT (2026-06-14):**
- Loot perms — `LootStore` now writes the loot dir `0700` + `secrets.jsonl`/`secrets.md` `0600` (owner-only).
- Destructive-command **self-guard** — `grin/safety.py` `is_self_destructive()` (narrow host/disk patterns:
  `rm -rf / ~ /*`, `mkfs`, `dd of=/dev/*`, redirect to a block device, fork bomb); the spine refuses +
  audits such a command at the execution chokepoint (`_execute_and_audit`, covers autonomous + approved).
  Override `GRIN_ALLOW_DESTRUCTIVE=1`. Verified it does NOT flag offensive tooling (sqlmap/nmap/hydra/…).
- No-secret-logging: the audit stores only a sha256 digest (already true); loot files are the only place
  values live. Unit-tested (`tests/test_safety.py`).

**STILL PENDING (operator's touches + opt-in encryption):** loot encryption-at-rest (age/agenix) as an
opt-in flag; any operator-specific denylist additions / secrets-retention policy. Tell me your touches.

---

## R4 — Deployment mode toggle: single-machine ↔ split (app local / compute on rig) — BUILT
**Built (2026-06-14):** inference-offload primitive (`resolve_ollama_url`) + the in-app toggle.
`grin/app/config.py` holds persisted deployment profiles (`local` / `split`), each bundling
`{ollama_url, env}`. The PyQt6 chrome has a **MODE: LOCAL ↔ SPLIT (RIG)** button — clicking it
persists the choice, sets `$GRIN_OLLAMA_URL` (inference) AND the tool-env override
(`GrinApi.set_backend` → `JobRunner(env=...)`), then re-checks the doctor at the new endpoint. So one
click rewires inference + tools together. Unit-tested (config round-trip, env threading, runner
override) + offscreen screenshot-verified. Defaults: split → rig IP for Ollama + ssh→rig for tools
(switch to an SSH tunnel for security per R3). Follow-up: in-app profile editing (host/url fields).
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
- **Inference offload** — DONE (2026-06-14): `OllamaClient` now resolves its endpoint via
  `resolve_ollama_url()` = explicit arg → `$GRIN_OLLAMA_URL` → localhost. Every engine construction
  (`_make_client`/`_make_executor_client`, doctor, bench) honors it automatically; `grin doctor` shows
  the resolved URL. So `GRIN_OLLAMA_URL=<rig/tunnel> grin engage …` already offloads inference. The
  remaining R4 work is the **in-app toggle/profiles** that set this + `tool_env` from the GUI.
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

---

## R6 — Hardware/RF tooling via Flipper Zero — FUTURE IDEA (no hardware yet)
**Status: parked — operator does not own a Flipper Zero yet. Capture only; revisit when hardware exists.**

**Idea:** drive a Flipper Zero as a Grin tool over its serial CLI (`/dev/ttyACM0`; libs `pyflipper`,
`flipperzero-cli`), executed by the runner on the host the device is physically attached to (the rig
in split mode). Opens a physical/RF attack surface — sub-GHz, NFC/RFID, IR, iButton, BadUSB.

**Why it's a deliberate sub-project, not a bolt-on (carry these constraints forward):**
1. **Doesn't fit the IP scope model** — needs a new notion of *physical/RF targets* (a badge, a 433MHz
   remote, a USB port) and new action classes (`rf-transmit`, `nfc-clone`, `badusb`, `ir`) in the spine.
2. **High-risk + physically intrusive + legally sensitive** — RF tx / RFID cloning / BadUSB can't be
   undone like a scan. Must be **ALWAYS human-gated** (never autonomous), even in own-lab. Hard spine rule.
3. **Physical presence required** — device attached to the runner host + control lib installed (the
   doctor/SP9 would check for it).

**Value:** physical/proximity authorized engagements (badge cloning, RF replay, BadUSB drops) —
orthogonal to Grin's current network strength. Only worth building once a device is on hand.

---

## R7 — Remote approval notifications (phone) — NOTIFY-ONLY BUILT (ntfy); actionable deferred
**Built (2026-06-14):** `grin/notify.py` `ntfy_send()` + the app's `_notify` pushes to **ntfy** when
`GRIN_NTFY_URL` is set (opt-in; self-host on the rig/LAN → nothing leaves operator control). Piggybacks
the existing gated/complete alert path, so your phone buzzes when an engagement needs approval or finishes.
Fail-soft (never blocks the run); unit-tested (sends when configured, silent when not). **Deferred:**
actionable Approve/Deny *from* the phone (needs a callback listener) + a headless-engage notify hook +
the Telegram backend. Set up: run ntfy on the rig, install the ntfy phone app, `export GRIN_NTFY_URL=...`.
**Goal:** when an engagement hits a gated action, ping the operator's **phone** — optionally with
**Approve / Deny** right from the notification — so a gated run can proceed while away. Hooks into the
existing spine pending-action / `grin gate` mechanism (a notifier fires when an action is queued gated).

**Two levels:**
- **Notify-only:** phone buzzes "awaiting approval — <action> on <target>"; operator approves at the
  console / `grin gate` later.
- **Notify + act:** Approve/Deny from the phone (a remote approval channel = C2 for offensive actions →
  treat with care, see guardrails).

**Channels:**
- **ntfy (self-hostable) — preferred.** HTTP POST to a topic; free phone app subscribes. Self-host on
  the rig/LAN → nothing leaves operator control (best fit for the local-only/privacy posture).
- **Telegram bot** — already used in [[project-portfolio-bot]] / [[project-agent-team]]; reliable;
  supports inline Approve/Deny buttons. Downside: routes through Telegram's servers (third-party).

**Security guardrails (REQUIRED):**
- **Opt-in / default-off** (additive; never changes default behavior).
- Notification content **leaves the box** → keep it **minimal/configurable** (no client secrets/full
  commands through a third party; self-hosted ntfy avoids the exposure).
- **Lock the channel to the operator** (single chat-id / token) — nobody else can approve.
- For **exploit/post-exploit** actions, keep remote-approve behind **extra auth** or require the console
  — approving offensive actions from a phone is the one place to stay conservative.
- The **audit trail still records** the approval + that it came via the remote channel (accountability intact).

**Recommendation:** ntfy self-hosted, notify+approve, locked to the operator.

---

## QoL — app polish — ALL BUILT (2026-06-14)
Restrained, on-brand QoL for the PyQt6 app — all keep the neat terminal aesthetic.

**Second wave BUILT (screenshot-verified, 322 tests):**
- **Resizable panes:** the live OBJECTIVES/FINDINGS/AUDIT grid is a `QSplitter` (drag the dividers).
- **`/` filter:** in the live view, `/` focuses a filter box that hides non-matching findings + audit rows
  (esc clears). Counts stay = totals.
- **In-app loot view:** `L` opens a `LootDialog` listing captured secrets (full values, click to copy, esc).
- **Doctor health dot:** a green/amber/dim `●` in the chrome reflecting the (off-thread) doctor result.
- **Elapsed clock + live counters:** the status bar shows OBJ/FIND/BLOCKED + an mm:ss run timer (ticks every
  poll even when panes are unchanged).

**First wave BUILT (the "top picks"):**
- **Keyboard-first nav:** `↑/↓` or `j/k` select engagement, `Enter` open, `Esc` back to boot, `r` refresh,
  `?` toggles a faint keymap hint line (extends the existing `A`/`D`). Selection shown via the yellow row
  highlight; window has StrongFocus so keys fire.
- **Esc-to-back** from live → boot.
- **Click-to-copy:** click a finding row or audit line → command copied to clipboard + a `COPIED` flash in
  the status bar.
- **Desktop notifications (local):** `desktop_notify` (macOS osascript / Linux notify-send, fail-soft) fires
  on a NEW gated action ("approval needed") and on completion (once each). R7 is the phone version.
- **Persistent window** size/position via QSettings (restore on open, save on close).
