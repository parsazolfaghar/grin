"""The `ronin` CLI — SP1 deliverable. A human stand-in for the future agents, so the
whole spine is exercisable now. Subcommands: engagement validate / run / gate / audit."""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from ronin.engagement import load_engagement, EngagementError, pending_path
from ronin.pending import PendingStore
from ronin.runner import build_runner, FakeRunner
from ronin.spine import submit_action, approve_action, deny_action


def cmd_validate(path: str) -> int:
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    print(f"OK: {eng.id} ({eng.name})")
    print(f"  mode={eng.mode} autonomy={eng.autonomy} state={eng.state}")
    print(f"  scope.in={eng.scope.include} exclude={eng.scope.exclude}")
    print(f"  roe.allowed={eng.roe.allowed_actions} windows={len(eng.roe.windows)}")
    print(f"  env={eng.env}")
    print(f"  audit_log={eng.audit_log}")
    return 0


def _parse_action_line(line: str):
    """Parse 'tool | command | target | declared_class'. Returns dict or None."""
    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 3 or not parts[0] or not parts[1] or not parts[2]:
        return None
    return {"tool": parts[0], "command": parts[1], "target": parts[2],
            "declared_class": parts[3] if len(parts) > 3 and parts[3] else None}


def run_loop(eng, *, runner, now: datetime, lines) -> int:
    """Drive the spine over an iterable of operator action lines (a real TTY in
    production; an iterator in tests). One action per line."""
    for raw in lines:
        raw = raw.strip()
        if not raw or raw in ("q", "quit", "exit"):
            break
        action = _parse_action_line(raw)
        if action is None:
            print("  ! expected: tool | command | target [| declared_class]")
            continue
        out = submit_action(eng, runner=runner, now=now, **action)
        if out.status == "executed":
            code = out.result.exit_code
            print(f"  [allow] executed (exit={code}) {out.record['result_digest']}")
        elif out.status == "pending":
            print(f"  [gate] held for approval — pending id {out.pending_id} "
                  f"(run `ronin gate`)")
        else:
            print(f"  [refuse] {out.reason}")
    return 0


def cmd_run(path: str) -> int:
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    runner = _runner_for(eng)
    print(f"engagement {eng.id} — submit actions as: tool | command | target [| class]")
    print("(blank line or 'q' to quit)")
    return run_loop(eng, runner=runner, now=datetime.now(),
                    lines=_stdin_lines("action> "))


def _stdin_lines(prompt: str):
    while True:
        try:
            yield input(prompt)
        except EOFError:
            break


def cmd_gate(path: str) -> int:
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    store = PendingStore(pending_path(eng))
    pend = store.list()
    if not pend:
        print("no pending actions.")
        return 0
    runner = _runner_for(eng)
    for entry in list(pend):
        print(f"\n[{entry['id']}] class={entry['resolved_class']} target={entry['target']}")
        print(f"    {entry['tool']}: {entry['command']}")
        choice = input("    approve / deny / skip? [a/d/s] ").strip().lower()
        if choice == "a":
            out = approve_action(eng, entry["id"], approver=_who(), runner=runner,
                                 now=datetime.now())
            print(f"    -> {out.status}" + (f": {out.reason}" if out.reason else ""))
        elif choice == "d":
            out = deny_action(eng, entry["id"], approver=_who())
            print(f"    -> {out.status} (denied)")
        else:
            print("    -> skipped (still pending)")
    return 0


def cmd_audit(path: str) -> int:
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    p = Path(eng.audit_log)
    if not p.exists():
        print("(no audit entries yet)")
        return 0
    for line in p.read_text().splitlines():
        rec = json.loads(line)
        extra = f" exit={rec.get('exit_code')}" if "exit_code" in rec else ""
        reason = f" — {rec['reason']}" if rec.get("reason") else ""
        print(f"{rec['ts']} [{rec['decision']}] {rec['action_class']} "
              f"{rec['target']} :: {rec['command']}{extra}{reason}")
    return 0


def _runner_for(eng):
    """Live runner from the engagement env; fall back to FakeRunner if the env
    cannot be built (e.g. docker extra missing) so the spine is still exercisable."""
    try:
        return build_runner(eng.env)
    except Exception as e:        # noqa: BLE001 - operator-facing fallback
        print(f"  (env runner unavailable: {e}; using FakeRunner)", file=sys.stderr)
        return FakeRunner()


def _who() -> str:
    import getpass
    try:
        return getpass.getuser()
    except Exception:             # noqa: BLE001
        return "operator"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ronin", description="Ronin engagement spine (SP1)")
    sub = parser.add_subparsers(dest="group", required=True)

    eng = sub.add_parser("engagement", help="engagement operations")
    eng_sub = eng.add_subparsers(dest="action", required=True)
    v = eng_sub.add_parser("validate", help="load + sanity-check an engagement file")
    v.add_argument("file")

    r = sub.add_parser("run", help="submit actions through the spine")
    r.add_argument("file")
    g = sub.add_parser("gate", help="approve/deny pending gated actions")
    g.add_argument("file")
    a = sub.add_parser("audit", help="print the audit trail")
    a.add_argument("file")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.group == "engagement" and args.action == "validate":
        return cmd_validate(args.file)
    if args.group == "run":
        return cmd_run(args.file)
    if args.group == "gate":
        return cmd_gate(args.file)
    if args.group == "audit":
        return cmd_audit(args.file)
    return 2


if __name__ == "__main__":
    sys.exit(main())
