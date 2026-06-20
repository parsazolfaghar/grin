# Security Policy

## Scope of this policy

This covers security issues in **grin itself** — the orchestrator, spine, helpers, and app. It does
**not** cover anything you do *with* grin against a target: grin is offensive tooling for
**authorized** testing only, and you are solely responsible for operating it lawfully and within a
scope you are permitted to test (see [LICENSE](LICENSE)).

## Reporting a vulnerability

Found a security problem in grin (e.g. a way the fail-closed spine could be bypassed, a scope-escape,
a secret-handling flaw, or an injection in a helper)?

- **Preferred:** open a [private security advisory](https://github.com/parsazolfaghar/grin/security/advisories/new)
  on this repository.
- Or open a regular issue **without** exploit details and ask for a private channel.

Please include: what the issue is, how to reproduce it, and the impact. Give a reasonable window to
fix before public disclosure. There's no bounty — this is a solo project — but credit is gladly given.

## What grin already does on its own behalf

For transparency, grin is built defensively:

- **Fail-closed spine** — every action is authorized against engagement scope/ROE; out-of-scope is
  refused, not run. The model cannot route around it.
- **Append-only audit log** of every allowed and refused action.
- **No bundled secrets / no proxy** — you bring your own API key; grin never transmits your key,
  targets, or traffic to the author or any third party. Loot stays local.
- **Self-host destruction guard** against commands that would damage the operator's own machine.

If you can defeat any of the above, that's exactly the kind of report worth sending.
