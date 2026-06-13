"""The `ronin` CLI — SP1 deliverable. A human stand-in for the future agents, so the
whole spine is exercisable now. Subcommands: engagement validate / run / gate / audit."""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from ronin.engagement import load_engagement, EngagementError, pending_path
from ronin.executor import execute_task, resume_task, DEFAULT_MODEL
from ronin.inference import OllamaClient
from ronin.orchestrator import orchestrate
from ronin.journal import Journal
from ronin.pending import PendingStore
from ronin.results import ResultStore, results_path
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
            if out.status == "executed" and out.result is not None:
                # bridge for the Executor's --resume: persist the full approved output
                ResultStore(results_path(eng)).put(
                    id=entry["id"], command=entry["command"],
                    output=out.result.output, exit_code=out.result.exit_code)
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


def _print_task_result(res) -> None:
    print(f"status: {res.status}")
    if res.pending_id:
        print(f"awaiting approval — pending id {res.pending_id} (run `ronin gate`, "
              f"then `ronin execute --resume {res.journal.path}`)")
    for f in res.findings:
        print(f"  [{f.severity}] {f.title} ({f.target}) — {f.tool}")
    print(f"journal: {res.journal.path}")


def cmd_execute(path: str, *, task: str, target: str, model: str, max_steps: int) -> int:
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    res = execute_task(eng, objective=task, target=target, client=_make_client(eng),
                       runner=_runner_for(eng), now=datetime.now(), model=model,
                       max_steps=max_steps, engagement_path=path)
    _print_task_result(res)
    return 0


def cmd_execute_resume(journal_file: str) -> int:
    journal = Journal.load(journal_file)
    try:
        eng = load_engagement(journal.engagement_path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    res = resume_task(eng, journal, client=_make_client(eng), runner=_runner_for(eng),
                      now=datetime.now(), result_store=ResultStore(results_path(eng)),
                      model=DEFAULT_MODEL)
    _print_task_result(res)
    return 0


def cmd_engage(path: str, *, goal: str, seeds: str, model: str, max_objectives: int,
               max_steps: int) -> int:
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    seed_list = [s.strip() for s in seeds.split(",") if s.strip()] if seeds else []
    res = orchestrate(eng, goal=goal, planner_client=_make_client(eng),
                      executor_client=_make_executor_client(eng), runner=_runner_for(eng),
                      now=datetime.now(), model=model, max_objectives=max_objectives,
                      max_steps=max_steps, seeds=seed_list, engagement_path=path)
    print(f"status: {res.status}")
    print(f"objectives run: {len(res.objectives_run)}")
    for f in res.findings:
        print(f"  [{f.severity}] {f.title} ({f.target}) — {f.tool}")
    for p in res.paused:
        o = p["objective"]
        print(f"  BLOCKED (awaiting approval): {o.objective} on {o.target} "
              f"— pending {p['pending_id']} (run `ronin gate`)")
    return 0


def _runner_for(eng):
    """Live runner from the engagement env; fall back to FakeRunner if the env
    cannot be built (e.g. docker extra missing) so the spine is still exercisable."""
    try:
        return build_runner(eng.env)
    except Exception as e:        # noqa: BLE001 - operator-facing fallback
        print(f"  (env runner unavailable: {e}; using FakeRunner)", file=sys.stderr)
        return FakeRunner()


def _make_client(eng):
    """The local model client. Separate function so tests can inject a FakeClient."""
    return OllamaClient()


def _make_executor_client(eng):
    """The Executor's model client. Separate factory so tests can inject a FakeClient and so a
    future SP can pin a different per-role model."""
    return OllamaClient()


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

    e = sub.add_parser("execute", help="run the AI Executor on one objective")
    e.add_argument("file", nargs="?", help="engagement file (omit with --resume)")
    e.add_argument("--task", help="the objective, in plain language")
    e.add_argument("--target", help="the authorized target host/URL")
    e.add_argument("--model", default=DEFAULT_MODEL, help="local model name")
    e.add_argument("--max-steps", type=int, default=12, dest="max_steps")
    e.add_argument("--resume", metavar="JOURNAL", help="resume a paused task from its journal")

    g2 = sub.add_parser("engage", help="run the Orchestrator on a high-level goal")
    g2.add_argument("file")
    g2.add_argument("--goal", required=True, help="the engagement goal, in plain language")
    g2.add_argument("--seeds", default="", help="optional comma-separated seed targets")
    g2.add_argument("--model", default=DEFAULT_MODEL, help="local model name")
    g2.add_argument("--max-objectives", type=int, default=10, dest="max_objectives")
    g2.add_argument("--max-steps", type=int, default=12, dest="max_steps")

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
    if args.group == "execute":
        if args.resume:
            return cmd_execute_resume(args.resume)
        if not args.file or not args.task or not args.target:
            print("execute needs <file> --task ... --target ... (or --resume <journal>)",
                  file=sys.stderr)
            return 2
        return cmd_execute(args.file, task=args.task, target=args.target,
                           model=args.model, max_steps=args.max_steps)
    if args.group == "engage":
        return cmd_engage(args.file, goal=args.goal, seeds=args.seeds, model=args.model,
                          max_objectives=args.max_objectives, max_steps=args.max_steps)
    return 2


if __name__ == "__main__":
    sys.exit(main())
