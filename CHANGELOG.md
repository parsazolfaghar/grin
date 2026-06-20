# Changelog

All notable changes to grin. Dates are when the work landed on `main`.

## 0.2.0 — 2026-06-19

The reliability + learning release: grin gets a memory, a deterministic last-mile, and a complete
one-button update.

### Added
- **Grin Brain** (`grin/brain.py`) — persistent cross-engagement learning. Detects the situation in a
  live run and injects the proven play every step; ships seeded and reinforces from real outcomes.
  `grin brain seed|list|path` (seed is idempotent — syncs new plays into an existing brain without
  wiping what it learned).
- **Deterministic auto-closer** (`grin/closer.py`) — when grin has a foothold but no proof and would
  otherwise give up, the code itself runs the matching helper through the fail-closed spine (no model
  in the loop). Covers: weak/default SSH creds (`cred-sweep`), command-injection (`web-rce`),
  sudo-NOPASSWD privesc (`sudo-gtfo`), SSTI→SUID privesc (`suid-hijack`), LFI/traversal→offline-crack
  (`lfi-crack`), SQL injection (`sqlmap`), and SSH-key lateral movement (`ssh-loot`, cross-objective).
- **nuclei integration** — broad CVE/misconfig coverage; hits become evidence-backed findings.
- New self-contained helpers: `cred-sweep`, `lfi-crack`, `sudo-gtfo` (+ `web-scan`, `grin-shell`).
- **Complementary Kali + BlackArch arsenal** — tools split (hydra/medusa + ProjectDiscovery on
  BlackArch) so a real engagement exercises both; `grin arsenal deploy` re-pushes helpers into the
  containers.
- `grin --version`.

### Changed
- **One-button update is now complete** (`scripts/update.sh`): git pull + reinstall **and**
  re-deploy helpers into the arsenal containers **and** sync the brain — so an update lands across all
  three layers, not just the Python code.
- Frictionless-within-authorization defaults (autonomous, auto-install tools).

### Fixed
- **Scope hardening:** closer commands are now scope-checked by their *true destination*, so a URL/host
  leaked in tool output (e.g. an nmap banner) can't be attacked out of scope.

## 0.1.0

Initial: fail-closed spine, orchestrator/executor, cloud/local brains, self-provisioning Docker
arsenal, ATT&CK catalog, PyQt6 desktop app.
