# Contributing

Thanks for the interest — grin is better for the feedback.

## First, the license

grin is **source-available, not open source**. The code is public so you can read it, evaluate it,
and run an unmodified copy for your own **authorized** testing. It is **not** licensed for copying,
modifying, redistributing, or building derivative/competing works (see [LICENSE](LICENSE)). That
shapes how contribution works here — please read this before opening a PR.

## What's very welcome

- **Bug reports** — open an issue with repro steps. Engine bugs, scope/spine edge cases, helper
  failures, and platform quirks (macOS / Windows / Linux) are all useful.
- **Feature ideas** — open an issue describing the use case. New deterministic closers, brain
  lessons, report formats, and platform support are good directions.
- **Security issues** — see [SECURITY.md](SECURITY.md) (use a private advisory).
- **Discussion** — questions about how a part works are fine; they often surface real gaps.

## Code contributions (PRs)

Because the project is proprietary, code contributions need a quick agreement first so the licensing
stays clean:

1. **Open an issue first** and say you'd like to implement it — get a thumbs-up before writing code.
2. By submitting a PR you agree your contribution is assigned to the project author and released under
   the project's license (you can't sublicense it elsewhere).
3. Keep PRs focused. Match the existing style.

## If you do get a PR going

- `pip install -e ".[dev,app]"`
- `ruff check grin/ tests/` — lint must pass (CI enforces it).
- `QT_QPA_PLATFORM=offscreen pytest -q` — full suite must stay green.
- New behavior needs tests (this codebase is test-driven).

## Ground rule

grin is offensive security tooling for **authorized** engagements only. Don't open issues, PRs, or
discussions that ask for help attacking systems you don't have permission to test. That's the one
thing that gets a hard no.
