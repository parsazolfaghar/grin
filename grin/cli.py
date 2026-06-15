"""The `grin` CLI — SP1 deliverable. A human stand-in for the future agents, so the
whole spine is exercisable now. Subcommands: engagement validate / run / gate / audit."""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import subprocess

from grin.engagement import load_engagement, EngagementError, pending_path
from grin.loot import LootStore, loot_dir
from grin.executor import execute_task, resume_task, DEFAULT_MODEL
from grin.inference import OllamaClient
from grin.orchestrator import orchestrate, resume_engagement
from grin.journal import Journal
from grin.pending import PendingStore
from grin.report_store import save_result, load_result, result_path
from grin.report import render_report, summarize_audit, llm_summary
from grin.results import ResultStore, results_path
from grin.runner import build_runner, FakeRunner
from grin.spine import submit_action, approve_action, deny_action
from grin.platform_info import detect_platform
from grin.doctor import run_doctor
from grin.installer import apply_fixes
from grin.bench.tasks import default_cases
from grin.bench.runner import run_bench
from grin.bench.report import to_text, to_json
from grin.lab.control import run_up, run_down, run_reset, run_status
from grin.lab.answers import load_answers as _load_lab_answers
from grin.lab.engagements import engagement_dict
from grin.lab.control import LAB_DIR as _LAB_DIR


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
                  f"(run `grin gate`)")
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
        print(f"awaiting approval — pending id {res.pending_id} (run `grin gate`, "
              f"then `grin execute --resume {res.journal.path}`)")
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


def _print_engagement_result(res) -> None:
    print(f"status: {res.status}")
    print(f"objectives run: {len(res.objectives_run)}")
    for f in res.findings:
        print(f"  [{f.severity}] {f.title} ({f.target}) — {f.tool}")
    for p in res.paused:
        o = p["objective"]
        print(f"  BLOCKED (awaiting approval): {o.objective} on {o.target} "
              f"— pending {p['pending_id']} (run `grin gate`)")


def cmd_engage(path: str, *, goal: str, seeds: str, model: str, max_objectives: int,
               max_steps: int, planner_model=None, recon_model=None, exploit_model=None) -> int:
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    seed_list = [s.strip() for s in seeds.split(",") if s.strip()] if seeds else []
    res = orchestrate(eng, goal=goal, planner_client=_make_client(eng),
                      executor_client=_make_executor_client(eng), runner=_runner_for(eng),
                      now=datetime.now(), model=model, planner_model=planner_model,
                      objective_models=_objective_models(recon_model, exploit_model),
                      max_objectives=max_objectives, max_steps=max_steps, seeds=seed_list,
                      engagement_path=path)
    save_result(result_path(eng), res)
    _print_engagement_result(res)
    return 0


def cmd_engage_resume(path: str, *, model: str, max_objectives: int, max_steps: int,
                      planner_model=None, recon_model=None, exploit_model=None) -> int:
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    try:
        prior = load_result(result_path(eng))
    except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
        print(f"no saved engagement result to resume ({e}); run `grin engage` first",
              file=sys.stderr)
        return 1
    store = ResultStore(results_path(eng))
    approved = [p for p in prior.paused if store.get(p["pending_id"]) is not None]
    if not approved:
        print("no approved blocked actions to resume; approve with `grin gate` first "
              "(nothing to resume)")
        return 0
    res = resume_engagement(eng, prior, planner_client=_make_client(eng),
                            executor_client=_make_executor_client(eng), runner=_runner_for(eng),
                            now=datetime.now(), model=model, max_objectives=max_objectives,
                            max_steps=max_steps, engagement_path=path,
                            planner_model=planner_model,
                            objective_models=_objective_models(recon_model, exploit_model))
    save_result(result_path(eng), res)
    _print_engagement_result(res)
    return 0


def cmd_report(path: str, *, out, model: str) -> int:
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    try:
        result = load_result(result_path(eng))
    except FileNotFoundError:
        print("no saved engagement result; run `grin engage` first", file=sys.stderr)
        return 1
    except (json.JSONDecodeError, KeyError) as e:
        print(f"cannot read saved engagement result ({e}); re-run `grin engage`",
              file=sys.stderr)
        return 1
    summary = llm_summary(_make_client(eng), model, result)
    md = render_report(eng, result, audit_summary=summarize_audit(eng.audit_log),
                       summary_text=summary)
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(md)
        print(f"report written to {out}")
    else:
        print(md)
    return 0


def cmd_loot(path: str) -> int:
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    rows = LootStore(loot_dir(eng)).all()
    if not rows:
        print("no secrets captured.")
        return 0
    for r in rows:
        print(f"[{r['label']}] {r['target']} :: {r['value']}  ({r['tool']} // {r['objective']})")
    return 0


_STATUS_TAG = {"ok": "[OK]  ", "missing": "[MISSING]", "broken": "[BROKEN]", "skipped": "[SKIP] "}


def _run_subprocess(cmd: str):
    try:
        p = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True, timeout=900)
        return ((p.stdout + p.stderr).strip(), p.returncode == 0)
    except Exception as e:  # noqa: BLE001 - surface any failure as a non-ok result
        return (str(e), False)


def _run_ollama_pull(cmd: str):
    return _run_subprocess(cmd)


def _ssh_prober(host: str) -> bool:
    try:
        return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                               host, "true"], capture_output=True, timeout=20).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _docker_prober(container: str):
    try:
        d = subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
        c = False
        if d:
            r = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"],
                               capture_output=True, text=True, timeout=10)
            c = container in r.stdout.split()
        return {"daemon": d, "container": c}
    except Exception:  # noqa: BLE001
        return {"daemon": False, "container": False}


def cmd_doctor(path, *, fix: bool, yes: bool, models, tools) -> int:
    plat = detect_platform()
    required = [m.strip() for m in models.split(",")] if isinstance(models, str) else (models or [DEFAULT_MODEL])
    tool_list = [t.strip() for t in tools.split(",")] if isinstance(tools, str) else (tools or ["nmap"])
    engagement = None
    runner = None
    if path:
        engagement = load_engagement(path)
        runner = build_runner(engagement.env)
    report = run_doctor(platform=plat, ollama=OllamaClient(), engagement=engagement,
                        runner=runner, required_models=required, tools=tool_list,
                        ssh_prober=_ssh_prober, docker_prober=_docker_prober)
    print(f"grin doctor — {plat.os} (pkg mgr: {plat.host_pkg_mgr})\n")
    for c in report.checks:
        line = f"  {_STATUS_TAG.get(c.status, c.status)}  {c.name}: {c.detail}"
        print(line)
        if c.fix and c.status not in ("ok", "skipped"):
            tag = "fix" if c.fix.kind == "auto" else "manual"
            print(f"            -> {tag}: {c.fix.command}")
    print()
    if not fix:
        if report.ok:
            print("All checks passed.")
            return 0
        print("Some checks need attention. Re-run with --fix to install the auto-fixable ones.")
        return 1

    fixable = report.fixable()
    if not fixable:
        print("Nothing auto-fixable. Address any [BROKEN]/[MISSING] advisory items manually.")
        return 0 if report.ok else 1

    def confirm(f):
        if yes:
            return True
        ans = input(f"Apply: {f.command} ? [y/N] ").strip().lower()
        return ans == "y"

    def env_install(cmd):
        # run the install inside the engagement env via the runner. Guard: env fixes only
        # arise from check_tools, which only runs with an engagement + runner, so runner is
        # never None here in practice — but fail safe rather than crash if that ever changes.
        if runner is None:
            return ("no engagement env to install into", False)
        res = runner.run(engagement.scope.include[0] if engagement and engagement.scope.include
                         else "localhost", cmd, timeout=900)
        return (res.output, res.exit_code == 0 and not res.timed_out)

    results = apply_fixes([c.fix for c in fixable], confirm=confirm, run=_run_subprocess,
                          ollama_pull=_run_ollama_pull, env_install=env_install)
    print()
    for r in results:
        state = "applied" if r.applied and r.ok else ("FAILED" if r.applied else "skipped")
        print(f"  {state}: {r.fix.label}")
    return 0 if all(r.ok for r in results) else 1


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


def _objective_models(recon_model, exploit_model):
    omap = {}
    if recon_model:
        omap["passive"] = recon_model
        omap["active-scan"] = recon_model
    if exploit_model:
        omap["exploit"] = exploit_model
        omap["post-exploit"] = exploit_model
    return omap or None


def _who() -> str:
    import getpass
    try:
        return getpass.getuser()
    except Exception:             # noqa: BLE001
        return "operator"


# Per-role default model pins — the current `grin bench` recommendation (deterministic + red-team-
# weighted, 2026-06-14; see docs/superpowers/results/). These MAY CHANGE as we run more benchmarks;
# update this one dict to re-pin. Every pin is overridable per run via --planner/--recon/--exploit-model.
DEFAULT_PINS = {
    "planner": "hermes3:8b",
    "recon": "qwen2.5-coder:7b",
    "exploit": "qwen3:14b",
}

DEFAULT_BENCH_MODELS = [
    "qwen3:14b", "qwen3:8b", "hermes3:8b",
    "whiterabbitneo:13b",   # local re-template of the GGUF (see docs/.../whiterabbitneo-13b.Modelfile);
                            # the raw hf.co GGUF ships a {{ .Prompt }} passthrough that drops the system msg
    "hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M",
    "qwen2.5-coder:7b", "dolphin3:8b",
]


def cmd_honeypot(path) -> int:
    """Advisory trap/honeypot assessment over a finished engagement's findings + audit. Never blocks."""
    from grin.honeypot import assess
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    findings = []
    try:
        findings = load_result(result_path(eng)).findings
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        pass
    audit_lines = []
    p = Path(eng.audit_log)
    if p.exists():
        for ln in p.read_text().splitlines():
            ln = ln.strip()
            if ln:
                try:
                    audit_lines.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
    a = assess(findings, audit_lines)
    tag = "SUSPECTED honeypot" if a.suspected else ("weak signals" if a.signals else "clear")
    print(f"trap assessment: {tag}  (score {a.score}/100)")
    for s in a.signals:
        print(f"  - {s}")
    print("  [advisory only — Grin does not block; the operator decides whether to engage]")
    return 0


def cmd_bench(*, models, roles, base_url, out, json_out, repeats=3) -> int:
    model_list = [m.strip() for m in models.split(",")] if models else list(DEFAULT_BENCH_MODELS)
    role_list = [r.strip() for r in roles.split(",")] if roles else ["planner", "recon", "exploit"]
    client = OllamaClient(base_url) if base_url else OllamaClient()
    report = run_bench(client, model_list, role_list, default_cases(), repeats=repeats)
    text = to_text(report)
    print(text)
    if out:
        with open(out, "w") as f:
            f.write(text + "\n")
    if json_out:
        with open(json_out, "w") as f:
            f.write(to_json(report) + "\n")
    return 0


def _lab_targets():
    return _load_lab_answers(str(_LAB_DIR / "answers.yaml"))


def cmd_lab(action: str, out_dir: str = None, runner: str = "grin-kali") -> int:
    if action == "up":
        return run_up()
    if action == "down":
        return run_down()
    if action == "reset":
        return run_reset()
    if action == "status":
        return run_status(runner_container=runner)
    if action == "engagements":
        import yaml
        from pathlib import Path
        dest = Path(out_dir or ".")
        dest.mkdir(parents=True, exist_ok=True)
        for t in _lab_targets():
            p = dest / f"lab-{t.id}.yaml"
            p.write_text(yaml.safe_dump(engagement_dict(t, runner_container=runner),
                                        sort_keys=False))
            print(f"wrote {p}")
        return 0
    print(f"unknown lab action {action!r}", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="grin", description="Grin engagement spine (SP1)")
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
    g2.add_argument("--goal", help="the engagement goal, in plain language")
    g2.add_argument("--seeds", default="", help="optional comma-separated seed targets")
    g2.add_argument("--model", default=DEFAULT_MODEL, help="local model name")
    g2.add_argument("--max-objectives", type=int, default=10, dest="max_objectives")
    g2.add_argument("--max-steps", type=int, default=12, dest="max_steps")
    g2.add_argument("--planner-model", default=DEFAULT_PINS["planner"], dest="planner_model",
                    help=f"model for the Orchestrator/Analyst (default: {DEFAULT_PINS['planner']})")
    g2.add_argument("--recon-model", default=DEFAULT_PINS["recon"], dest="recon_model",
                    help=f"model for passive/active-scan objectives (default: {DEFAULT_PINS['recon']})")
    g2.add_argument("--exploit-model", default=DEFAULT_PINS["exploit"], dest="exploit_model",
                    help=f"model for exploit/post-exploit objectives (default: {DEFAULT_PINS['exploit']})")
    g2.add_argument("--resume", action="store_true", help="continue a paused engagement after `grin gate` approvals")

    rp = sub.add_parser("report", help="render a Markdown report from a finished engagement")
    rp.add_argument("file")
    rp.add_argument("-o", "--out", default=None, help="output file (default: stdout)")
    rp.add_argument("--model", default=DEFAULT_MODEL, help="local model for the optional summary")

    hp = sub.add_parser("honeypot", help="advisory honeypot/trap assessment of an engagement")
    hp.add_argument("file")

    lt = sub.add_parser("loot", help="print captured secrets for an engagement")
    lt.add_argument("file")

    dr = sub.add_parser("doctor", help="check the environment + permission-gated installs")
    dr.add_argument("file", nargs="?", help="engagement file (omit for host-only checks)")
    dr.add_argument("--fix", action="store_true", help="install auto-fixable missing items (asks per item)")
    dr.add_argument("--yes", action="store_true", help="auto-confirm all fixes (with --fix)")
    dr.add_argument("--models", default=None, help="comma-separated required models (default: the base model)")
    dr.add_argument("--tools", default=None, help="comma-separated expected arsenal tools (default: nmap)")

    ap = sub.add_parser("app", help="open the Grin desktop app (needs the [app] extra)")
    ap.add_argument("dir", nargs="?", default=".", help="folder of engagement .yaml files")

    bn = sub.add_parser("bench", help="benchmark local models for each role")
    bn.add_argument("--models", default=None, help="comma-separated model names (default: the candidate set)")
    bn.add_argument("--roles", default=None, help="comma-separated roles (default: planner,recon,exploit)")
    bn.add_argument("--base-url", default=None, dest="base_url", help="Ollama base URL (default: local)")
    bn.add_argument("--out", default=None, help="write the text report to a file")
    bn.add_argument("--json", default=None, dest="json_out", help="write the JSON results to a file")
    bn.add_argument("--repeats", type=int, default=3, help="samples per case (mean score, median latency)")

    p_lab = sub.add_parser("lab", help="manage the isolated flag-lab targets")
    p_lab.add_argument("action", choices=["up", "down", "reset", "status", "engagements"])
    p_lab.add_argument("out_dir", nargs="?", default=None,
                       help="(engagements) directory to write engagement YAMLs into")
    p_lab.add_argument("--runner", default="grin-kali", help="runner container name")

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
        if args.resume:
            return cmd_engage_resume(args.file, model=args.model,
                                     max_objectives=args.max_objectives, max_steps=args.max_steps,
                                     planner_model=args.planner_model, recon_model=args.recon_model,
                                     exploit_model=args.exploit_model)
        if not args.goal:
            print("engage needs --goal (or --resume)", file=sys.stderr)
            return 2
        return cmd_engage(args.file, goal=args.goal, seeds=args.seeds, model=args.model,
                          max_objectives=args.max_objectives, max_steps=args.max_steps,
                          planner_model=args.planner_model, recon_model=args.recon_model,
                          exploit_model=args.exploit_model)
    if args.group == "report":
        return cmd_report(args.file, out=args.out, model=args.model)
    if args.group == "loot":
        return cmd_loot(args.file)
    if args.group == "honeypot":
        return cmd_honeypot(args.file)
    if args.group == "doctor":
        return cmd_doctor(args.file, fix=args.fix, yes=args.yes, models=args.models, tools=args.tools)
    if args.group == "app":
        from grin.app.launch import main as app_main
        return app_main([args.dir])
    if args.group == "bench":
        return cmd_bench(models=args.models, roles=args.roles, base_url=args.base_url,
                         out=args.out, json_out=args.json_out, repeats=args.repeats)
    if args.group == "lab":
        return cmd_lab(args.action, out_dir=args.out_dir, runner=args.runner)
    return 2


if __name__ == "__main__":
    sys.exit(main())
