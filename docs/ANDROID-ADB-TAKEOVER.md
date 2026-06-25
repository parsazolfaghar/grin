# Android / ADB takeover playbook

## Why this exists — the J7 engagement (2026-06-24)

`grin engage` was run against a real Android phone (Samsung Galaxy J7, `SM-J700F`, Android 6.0.1)
on the LAN at `192.168.1.116`, exposing **ADB on TCP 5555** with no auth. Cloud brain
(`deepseek-reasoner`), `--aggressive`, ROE `[passive, active-scan, exploit]`.

**What grin got right:**
- Recon found 5555; the reasoner recognised it despite nmap's `freeciv` mislabel
  (*"Port 5555 is the default ADB port"*) and pivoted to `adb`.
- It autonomously connected and got a shell — `uid=2000(shell) ... context=u:r:shell:s0` — the same
  foothold a human gets by hand. Adaptive reasoning beyond its catalog: a win.
- The ROE held: a dozen post-exploit catalog tools (web-rce, sqlmap, sudo-gtfo, lfi-crack) were
  auto-refused because `post-exploit` wasn't in the engagement's allowed_actions.

**The two gaps it exposed:**
1. **No Android/ADB playbook.** grin's catalog is web/SSH/cmdi-shaped, so it wasted ~12 attempts
   assuming a web app on the box (`web-rce --url http://192.168.1.116:2222 ...`). It had no
   ADB-native technique and had to improvise.
2. **CTF-brained.** The goal said *"demonstrate impact (screenshot, pull data)"*, but grin reduced
   that to *"find the flag"* — ran `find / -name flag*`, got only `/sys/.../flags` noise. On a real
   device there is no flag; **the impact IS the screenshot / data / control.**

## The fix — an ADB-native technique chain ending in screen takeover

Operator's goal (verbatim): *"when I run, I want it to take control of my Samsung and a remote
control on my desktop where I can control everything like a screen mirror."* The right tool for that
is **scrcpy** (live screen mirror + full mouse/keyboard control over ADB).

### Deliverables
1. **`grin/tools/adbtakeover.py` → `adb-takeover` helper** (this commit). Deterministic Android
   takeover: connect to exposed ADB, fingerprint the device, list user apps, capture a screenshot as
   proof, and (with `--mirror`) launch **scrcpy** for a live, controllable mirror on the operator
   desktop. Same "give the model a deterministic capability" pattern as `web-rce` / `ssh-loot`.
2. **Catalog entries** in `catalog/attack_catalog.yaml`, `applies_when: "port:5555"`:
   - `T1021` Remote Services — ADB → `adb-takeover --target {target}` (action_class: exploit)
   - `T1113` Screen Capture (Android) → `adb-takeover --target {target} --screenshot` (post-exploit)
   - `T1219` Remote Access Software — scrcpy mirror/control → `adb-takeover --target {target} --mirror`
     (post-exploit)
3. **Prompt guidance** in `grin/prompts.py`: when a target exposes ADB/5555, PREFER `adb-takeover`
   over generic web tools; the impact on a phone is screenshot + data + a scrcpy mirror, NOT a flag.
4. **Deployment:** `adb` and `scrcpy` must be present on the runner. For `env.kind: local` on the
   kult box (NixOS + Hyprland), add `pkgs.scrcpy` + `pkgs.android-tools` and the scrcpy window opens
   on the operator's own desktop — which is exactly the requested "control from my desktop."

### Usage (operator)
Run with `post-exploit` in the ROE so grin is allowed to take control:
```yaml
roe:
  allowed_actions: [passive, active-scan, exploit, post-exploit]
```
```
grin engage j7.yaml --goal "Take control of the Android phone at 192.168.1.116 via exposed ADB on 5555: get a shell, screenshot it, and open a live scrcpy screen-mirror I can control from my desktop." --seeds 192.168.1.116 --aggressive
```

### Note — no impact/DoS rule still holds
Screen mirror + control is **interaction/collection**, not destruction. It stays inside grin's
permanent "no impact/DoS/destructive techniques" line; scrcpy never wipes, bricks, or denies service.

## Status
- [x] `adb-takeover` tool + test (6 tests green)
- [x] catalog entries (port:5555): T1021 ADB remote-services, T1113 screen-capture, T1219 scrcpy mirror
- [x] prompt guidance (ADB=phone -> prefer adb-takeover; impact = screenshot+mirror+data, NOT a flag)
- [ ] make `adb-takeover` invocable on the runner (deploy step, like web-rce/ssh-loot)
- [ ] scrcpy + android-tools on the kult runner (NixOS)
- [ ] live re-test against the J7
