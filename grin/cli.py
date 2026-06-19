"""The `grin` CLI — SP1 deliverable. A human stand-in for the future agents, so the
whole spine is exercisable now. Subcommands: engagement validate / run / gate / audit."""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import subprocess

from grin.engagement import load_engagement, validate_engagement, EngagementError, pending_path
from grin.loot import LootStore, loot_dir
from grin.executor import execute_task, resume_task, DEFAULT_MODEL
from grin.inference import OllamaClient, make_inference_client, active_backend
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
from grin.arsenal import (run_up as arsenal_up, run_down as arsenal_down,
                          run_status as arsenal_status, run_add as arsenal_add)
from grin.lab.answers import load_answers as _load_lab_answers
from grin.lab.engagements import engagement_dict
from grin.lab.control import LAB_DIR as _LAB_DIR
from grin.labbench.matrix import load_matrix as _load_matrix
from grin.labbench.runner import run_sweep
from grin.labbench.report import aggregate, to_text as _labbench_to_text
from grin.labbench.scorers import RunArtifact as _RunArtifact

from pathlib import Path as _Path
DEFAULT_CATALOG_PATH = str(_Path(__file__).resolve().parents[1] / "catalog" / "attack_catalog.yaml")


def _load_catalog_or_none(path=DEFAULT_CATALOG_PATH):
    try:
        from grin.catalog import load_catalog
        return load_catalog(path)
    except Exception:  # noqa: BLE001 - a missing/broken catalog must not break a normal engage
        return None


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
               max_steps: int, planner_model=None, recon_model=None, exploit_model=None,
               aggressive: bool = False, strength=None, stealth=None,
               medic_patches: bool = False) -> int:
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    # CLI --strength/--stealth override the engagement's own fields (frozen -> rebuild)
    import dataclasses
    if strength is not None:
        eng = dataclasses.replace(eng, strength=strength)
    if stealth is not None:
        eng = dataclasses.replace(eng, stealth=stealth)
    seed_list = [s.strip() for s in seeds.split(",") if s.strip()] if seeds else []
    # honor the engagement's strength level: aggressive levels trigger the sweep; budgets act as a
    # floor (the --aggressive flag still wins). Stealth is applied separately by the spine (eng.stealth).
    from grin.strength import strength_params
    sp = strength_params(getattr(eng, "strength", "normal"))
    aggressive = aggressive or sp.aggressive or getattr(eng, "aggressive", False)
    max_objectives = max(max_objectives, sp.max_objectives)
    max_steps = max(max_steps, sp.max_steps)
    catalog = _load_catalog_or_none() if aggressive else None
    if aggressive:
        from grin.aggressive import DEFAULT_AGGRESSIVE_BUDGET
        max_objectives = max(max_objectives, DEFAULT_AGGRESSIVE_BUDGET["max_objectives"])
        max_steps = max(max_steps, DEFAULT_AGGRESSIVE_BUDGET["max_steps"])
    pins = _resolve_pins(planner=planner_model, recon=recon_model, exploit=exploit_model)
    _print_backend_notice(pins)
    _record_cloud_backend(eng, pins)
    res = orchestrate(eng, goal=goal, planner_client=_make_client(eng),
                      executor_client=_make_executor_client(eng), runner=_runner_for(eng),
                      now=datetime.now(), model=pins["planner"], planner_model=pins["planner"],
                      objective_models=_objective_models(pins["recon"], pins["exploit"]),
                      max_objectives=max_objectives, max_steps=max_steps, seeds=seed_list,
                      engagement_path=path, aggressive=aggressive, catalog=catalog,
                      medic_patches=medic_patches)
    save_result(result_path(eng), res)
    _print_engagement_result(res)
    return 0


def cmd_engagement_playbooks() -> int:
    from grin.playbooks import PLAYBOOKS, playbook_names
    print("Available playbooks:\n")
    for name in playbook_names():
        print(f"  {name:<18} {PLAYBOOKS[name]['blurb']}")
    print("\nUse: grin engagement new --playbook <name> --id <id> --scope <targets>")
    return 0


def cmd_engagement_new(*, playbook: str, eid: str, name, scope: str, exclude: str,
                       env: str, out) -> int:
    import yaml
    from grin.playbooks import PlaybookError, build_engagement
    scope_in = [s.strip() for s in scope.split(",") if s.strip()]
    scope_ex = [s.strip() for s in exclude.split(",") if s.strip()]
    if not scope_in:
        print("--scope must list at least one in-scope target", file=sys.stderr)
        return 2
    try:
        data = build_engagement(playbook, eid=eid, name=name or eid, scope_in=scope_in,
                                scope_exclude=scope_ex, env={"kind": env})
    except PlaybookError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 2
    # round-trip through the validator so we never write a file `grin` would later reject
    try:
        validate_engagement(data)
    except EngagementError as e:
        print(f"INTERNAL: playbook produced an invalid engagement ({e})", file=sys.stderr)
        return 1
    out_path = out or f"{eid}.yaml"
    if Path(out_path).exists():
        print(f"refusing to overwrite existing file: {out_path}", file=sys.stderr)
        return 1
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(yaml.safe_dump(data, sort_keys=False))
    print(f"wrote {out_path} (playbook: {playbook}). Review it, then: "
          f"grin engage {out_path} --goal '<your goal>'")
    return 0


def cmd_ci(path: str, *, goal: str, seeds: str, model: str, max_objectives: int,
           max_steps: int, fail_on: str, sarif_out=None, aggressive: bool = False) -> int:
    """Headless CI/pipeline mode: run the engagement, then GATE the build on finding severity.
    Exits 2 if any finding is at/above --fail-on, else 0 (1 stays for operational errors). Writes
    a SARIF file when --sarif is given so the pipeline can upload it to code-scanning."""
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    seed_list = [s.strip() for s in seeds.split(",") if s.strip()] if seeds else []
    pins = _resolve_pins()
    catalog = _load_catalog_or_none() if aggressive else None
    res = orchestrate(eng, goal=goal, planner_client=_make_client(eng),
                      executor_client=_make_executor_client(eng), runner=_runner_for(eng),
                      now=datetime.now(), model=pins["planner"], planner_model=pins["planner"],
                      objective_models=_objective_models(pins["recon"], pins["exploit"]),
                      max_objectives=max_objectives, max_steps=max_steps, seeds=seed_list,
                      engagement_path=path, aggressive=aggressive, catalog=catalog)
    save_result(result_path(eng), res)
    if sarif_out:
        from grin.report import render_sarif
        Path(sarif_out).parent.mkdir(parents=True, exist_ok=True)
        Path(sarif_out).write_text(render_sarif(eng, res))
        print(f"SARIF written to {sarif_out}")
    from grin.cigate import ci_gate
    code, offending, summary = ci_gate(res.findings, fail_on=fail_on)
    print(summary)
    for f in offending:
        print(f"  [{f.severity}] {f.title} — {f.target}")
    return code


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
    pins = _resolve_pins(planner=planner_model, recon=recon_model, exploit=exploit_model)
    _print_backend_notice(pins)
    _record_cloud_backend(eng, pins)
    res = resume_engagement(eng, prior, planner_client=_make_client(eng),
                            executor_client=_make_executor_client(eng), runner=_runner_for(eng),
                            now=datetime.now(), model=pins["planner"], max_objectives=max_objectives,
                            max_steps=max_steps, engagement_path=path,
                            planner_model=pins["planner"],
                            objective_models=_objective_models(pins["recon"], pins["exploit"]))
    save_result(result_path(eng), res)
    _print_engagement_result(res)
    return 0


def cmd_report(path: str, *, out, model: str, fmt: str = "markdown") -> int:
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

    if fmt == "sarif":
        from grin.report import render_sarif
        doc = render_sarif(eng, result)
    elif fmt == "html":
        from grin.report import render_html
        doc = render_html(eng, result, summary_text=summary)
    else:
        _audit_records = []
        _ap = _Path(eng.audit_log)
        if _ap.exists():
            for _ln in _ap.read_text().splitlines():
                _ln = _ln.strip()
                if _ln:
                    try:
                        _audit_records.append(json.loads(_ln))
                    except json.JSONDecodeError:
                        continue
        from grin.discoveries import discover, gather_records
        _disc = discover(gather_records(eng))
        doc = render_report(eng, result, audit_summary=summarize_audit(eng.audit_log),
                            summary_text=summary, catalog=_load_catalog_or_none(),
                            audit_records=_audit_records, discoveries=_disc)
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(doc)
        print(f"report written to {out}")
    else:
        print(doc)
    return 0


def cmd_discoveries(path: str) -> int:
    try:
        eng = load_engagement(path)
    except EngagementError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        return 1
    from grin.discoveries import discover, gather_records
    from grin.report import render_discovered
    d = discover(gather_records(eng))
    text = render_discovered(d)
    print(text if text else "no discoveries yet")
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
    _backend = active_backend()
    _client = make_inference_client() if _backend == "openai" else OllamaClient()
    _print_backend_notice(_resolve_pins())
    report = run_doctor(platform=plat, ollama=_client, engagement=engagement,
                        runner=runner, required_models=required, tools=tool_list,
                        ssh_prober=_ssh_prober, docker_prober=_docker_prober,
                        backend=_backend)
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
    """The inference client for the active backend. Separate function so tests can inject a FakeClient."""
    return make_inference_client()


def _make_executor_client(eng):
    """The Executor's inference client for the active backend. Separate factory so tests can inject a FakeClient and so a
    future SP can pin a different per-role model."""
    return make_inference_client()


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

CLOUD_DEFAULT_PINS = {
    # R1 reasoner for PLANNING/judgment (few calls per engagement -> small cost; measurably plans
    # smarter — skips needless recon when the goal already names the service). Per-step recon/exploit
    # stay on fast/cheap chat. Overridable via --planner-model/--recon-model/--exploit-model.
    "planner": "deepseek-reasoner",
    "recon": "deepseek-chat",
    "exploit": "deepseek-chat",
}


def _resolve_pins(*, planner=None, recon=None, exploit=None) -> dict:
    """Per-role models for the active backend. Precedence per role: explicit CLI value >
    GRIN_<ROLE>_MODEL env (e.g. set in ~/.grin/env) > the backend's default set (CLOUD_DEFAULT_PINS
    for openai, DEFAULT_PINS for ollama). The env layer lets ~/.grin/env alone point a non-DeepSeek
    cloud backend (Cerebras) at its own model — no code edit or per-run CLI flag."""
    import os as _os
    base = CLOUD_DEFAULT_PINS if active_backend() == "openai" else DEFAULT_PINS
    return {
        "planner": planner or _os.environ.get("GRIN_PLANNER_MODEL") or base["planner"],
        "recon": recon or _os.environ.get("GRIN_RECON_MODEL") or base["recon"],
        "exploit": exploit or _os.environ.get("GRIN_EXPLOIT_MODEL") or base["exploit"],
    }


def _print_backend_notice(pins) -> None:
    """One-line visibility of the resolved model backend so auto-selection is never silent."""
    from grin.inference import resolve_ollama_url
    import os as _osmod
    if active_backend() == "openai":
        url = _osmod.environ.get("GRIN_MODEL_URL", "")
        print(f"[backend] cloud · {pins['planner']} · {url}", file=sys.stderr)
    else:
        print(f"[backend] local · {pins['planner']} · {resolve_ollama_url()}", file=sys.stderr)


def _record_cloud_backend(eng, pins) -> None:
    """Cloud backend active: append a backend marker to the audit log (always) and, for client
    engagements, print a loud warning that data goes to a third party (warn-only — the operator's
    contract is the authorization)."""
    if active_backend() != "openai":
        return
    import json as _json
    import os as _os
    from pathlib import Path as _Path
    url = _os.environ.get("GRIN_MODEL_URL", "")
    marker = {"event": "model-backend", "backend": "openai", "url": url,
              "planner": pins["planner"], "recon": pins["recon"], "exploit": pins["exploit"]}
    ap = _Path(eng.audit_log)
    ap.parent.mkdir(parents=True, exist_ok=True)
    with ap.open("a") as fh:
        fh.write(_json.dumps(marker) + "\n")
    if eng.mode == "client":
        print("=" * 70, file=sys.stderr)
        print("WARNING: cloud model backend active for a CLIENT engagement.", file=sys.stderr)
        print("  Targets, findings, and credentials will be sent to a THIRD-PARTY endpoint:",
              file=sys.stderr)
        print(f"  {url}", file=sys.stderr)
        print("  Ensure this is authorized in your engagement contract/ROE.", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

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


def cmd_arsenal(action: str, tool: str = None) -> int:
    if action == "up":
        return arsenal_up()
    if action == "down":
        return arsenal_down()
    if action == "status":
        return arsenal_status()
    if action == "add":
        if not tool:
            print("usage: grin arsenal add <tool>", file=sys.stderr)
            return 2
        return arsenal_add(tool)
    print(f"unknown arsenal action {action!r}", file=sys.stderr)
    return 2


def _clear_engagement_artifacts(eng):
    """Remove this engagement's append-only artifacts so a benchmark run is scored clean."""
    import glob
    import shutil
    from pathlib import Path
    try:
        Path(eng.audit_log).unlink(missing_ok=True)
    except Exception:  # noqa: BLE001
        pass
    for path in (loot_dir(eng), result_path(eng)):
        p = Path(path)
        try:
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass
    # remove any journal files for this engagement (e.g. <id>.*.journal.json)
    import os
    base, _ext = os.path.splitext(eng.audit_log)
    for j in glob.glob(f"{base}.*.journal.json"):
        try:
            Path(j).unlink(missing_ok=True)
        except Exception:  # noqa: BLE001
            pass


def _labbench_reset_fn(runner="grin-kali"):
    """Return a callable that resets the lab to pristine state before each run."""
    return lambda: run_reset()


def _labbench_collect_fn(runner="grin-kali"):
    """Build a collect_fn that runs ONE clean live engagement for a target with given pins."""
    import contextlib
    import io
    import time
    from pathlib import Path

    def collect(target, pins):
        eng_path = str(Path("examples/lab") / f"lab-{target.id}.yaml")
        eng = load_engagement(eng_path)
        _clear_engagement_artifacts(eng)   # clean slate so the score reflects only this run
        buf = io.StringIO()
        t0 = time.monotonic()
        with contextlib.redirect_stdout(buf):
            res = orchestrate(
                eng, goal="capture the flag",
                planner_client=_make_client(eng), executor_client=_make_executor_client(eng),
                runner=_runner_for(eng), now=datetime.now(),
                model=pins["planner"], planner_model=pins["planner"],
                objective_models=_objective_models(pins.get("recon"), pins.get("exploit")),
                max_objectives=8, max_steps=40, seeds=[], engagement_path=eng_path)
        dur = time.monotonic() - t0
        transcript = buf.getvalue()
        finding_text = " ".join(f"{f.title} {f.evidence} {f.command}" for f in res.findings)
        loot_text = ""
        try:
            loot_text = json.dumps(LootStore(loot_dir(eng)).all())
        except Exception:  # noqa: BLE001
            pass
        audit = []
        p = Path(eng.audit_log)
        if p.exists():
            for ln in p.read_text().splitlines():
                ln = ln.strip()
                if ln:
                    try:
                        audit.append(json.loads(ln))
                    except json.JSONDecodeError:
                        continue
        blob = " ".join([finding_text, loot_text, json.dumps(audit), transcript])
        return _RunArtifact(target_id=target.id, blob=blob, finding_text=finding_text,
                            audit=audit, transcript=transcript, duration_s=dur)
    return collect


def cmd_labbench(*, matrix_path: str, out: str, runner: str = "grin-kali") -> int:
    from dataclasses import asdict
    from pathlib import Path
    matrix = _load_matrix(matrix_path)
    targets = _lab_targets()
    rows = run_sweep(matrix, targets,
                     reset_fn=_labbench_reset_fn(runner),
                     collect_fn=_labbench_collect_fn(runner))
    aggs = aggregate(rows)
    text = _labbench_to_text(aggs)
    print(text)
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(text)
        runs_json = [{"role": role, "model": model, **asdict(score)}
                     for role, model, score in rows]
        runs_path = Path(out).with_name("runs.json")
        runs_path.write_text(json.dumps(runs_json, indent=2))
        print(f"\nwrote {out} and {runs_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="grin", description="Grin engagement spine (SP1)")
    sub = parser.add_subparsers(dest="group", required=True)

    eng = sub.add_parser("engagement", help="engagement operations")
    eng_sub = eng.add_subparsers(dest="action", required=True)
    v = eng_sub.add_parser("validate", help="load + sanity-check an engagement file")
    v.add_argument("file")
    from grin.playbooks import playbook_names as _pb_names
    nw = eng_sub.add_parser("new", help="scaffold an engagement file from a playbook")
    nw.add_argument("--playbook", required=True, choices=_pb_names(),
                    help="engagement template (sets mode/ROE/autonomy/strength/stealth)")
    nw.add_argument("--id", required=True, dest="eid", help="engagement id (used in filenames)")
    nw.add_argument("--name", default=None, help="human label (default: derived from --id)")
    nw.add_argument("--scope", required=True,
                    help="comma-separated in-scope targets (hosts/CIDRs/URL globs)")
    nw.add_argument("--exclude", default="", help="comma-separated out-of-scope targets")
    nw.add_argument("--env", default="local", choices=["local", "ssh", "docker", "arsenal", "auto"],
                    help="runner environment kind (default: local)")
    nw.add_argument("-o", "--out", default=None, help="output file (default: <id>.yaml)")
    eng_sub.add_parser("playbooks", help="list available engagement playbooks")

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
    g2.add_argument("--planner-model", default=None, dest="planner_model",
                    help="model for the Orchestrator/Analyst (default: per backend — "
                         f"{DEFAULT_PINS['planner']} local / {CLOUD_DEFAULT_PINS['planner']} cloud)")
    g2.add_argument("--recon-model", default=None, dest="recon_model",
                    help="model for passive/active-scan objectives (default: per backend)")
    g2.add_argument("--exploit-model", default=None, dest="exploit_model",
                    help="model for exploit/post-exploit objectives (default: per backend)")
    g2.add_argument("--strength", default=None, choices=["recon", "normal", "aggressive", "max"],
                    help="attack strength (overrides the engagement's strength)")
    g2.add_argument("--stealth", default=None, choices=["off", "quiet", "paranoid"],
                    help="stealth level (overrides the engagement's stealth)")
    g2.add_argument("--resume", action="store_true", help="continue a paused engagement after `grin gate` approvals")
    g2.add_argument("--aggressive", action="store_true",
        help="exhaustive mode: sweep the ATT&CK catalog (more attempts, same guardrails)")
    g2.add_argument("--medic-patches", action="store_true",
        help="when the Medic hits a capability wall, draft a code-patch PROPOSAL for review "
             "(written to audit/<id>.medic-patch.md; never auto-applied)")

    ci = sub.add_parser("ci", help="headless CI mode: run the engagement, fail the build "
                                   "(exit 2) on findings at/above a severity threshold")
    ci.add_argument("file")
    ci.add_argument("--goal", help="the engagement goal, in plain language")
    ci.add_argument("--seeds", default="", help="optional comma-separated seed targets")
    ci.add_argument("--model", default=DEFAULT_MODEL, help="local model name")
    ci.add_argument("--max-objectives", type=int, default=10, dest="max_objectives")
    ci.add_argument("--max-steps", type=int, default=12, dest="max_steps")
    ci.add_argument("--fail-on", dest="fail_on", default="high",
                    choices=["critical", "high", "medium", "low", "info"],
                    help="fail the build on a finding at or above this severity (default: high)")
    ci.add_argument("--sarif", dest="sarif_out", default=None,
                    help="also write a SARIF file for the pipeline to upload to code-scanning")
    ci.add_argument("--aggressive", action="store_true",
                    help="exhaustive mode: sweep the ATT&CK catalog (more attempts, same guardrails)")

    rp = sub.add_parser("report", help="render a report from a finished engagement "
                                       "(markdown / sarif / html)")
    rp.add_argument("file")
    rp.add_argument("-o", "--out", default=None, help="output file (default: stdout)")
    rp.add_argument("--format", dest="format", choices=["markdown", "sarif", "html"],
                    default="markdown",
                    help="markdown (default), sarif (CI/code-scanning), or html (shareable)")
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

    p_lb = sub.add_parser("labbench", help="benchmark local LLMs per role against the flag-lab")
    p_lb.add_argument("--matrix", default="lab/matrix.yaml", dest="matrix_path")
    p_lb.add_argument("--out", default="lab/results/ranking.txt")
    p_lb.add_argument("--runner", default="grin-kali")

    p_ars = sub.add_parser("arsenal", help="provision/manage the Kali+BlackArch tool arsenals")
    p_ars.add_argument("action", choices=["up", "down", "status", "add"])
    p_ars.add_argument("tool", nargs="?", default=None, help="(add) tool to install")

    dc = sub.add_parser("discoveries", help="print deterministic discoveries from an engagement's results store")
    dc.add_argument("file")

    return parser


def main(argv=None) -> int:
    from grin.config import load_env_file
    load_env_file()
    from grin.dockerenv import ensure_docker_host
    ensure_docker_host()   # auto-point DOCKER_HOST at Colima/Docker if unset (so docker envs just work)
    args = build_parser().parse_args(argv)
    if args.group == "engagement" and args.action == "validate":
        return cmd_validate(args.file)
    if args.group == "engagement" and args.action == "playbooks":
        return cmd_engagement_playbooks()
    if args.group == "engagement" and args.action == "new":
        return cmd_engagement_new(playbook=args.playbook, eid=args.eid, name=args.name,
                                  scope=args.scope, exclude=args.exclude, env=args.env,
                                  out=args.out)
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
                          exploit_model=args.exploit_model, aggressive=args.aggressive,
                          strength=args.strength, stealth=args.stealth,
                          medic_patches=args.medic_patches)
    if args.group == "ci":
        if not args.goal:
            print("ci needs --goal", file=sys.stderr)
            return 2
        return cmd_ci(args.file, goal=args.goal, seeds=args.seeds, model=args.model,
                      max_objectives=args.max_objectives, max_steps=args.max_steps,
                      fail_on=args.fail_on, sarif_out=args.sarif_out, aggressive=args.aggressive)
    if args.group == "report":
        return cmd_report(args.file, out=args.out, model=args.model, fmt=args.format)
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
    if args.group == "labbench":
        return cmd_labbench(matrix_path=args.matrix_path, out=args.out, runner=args.runner)
    if args.group == "arsenal":
        return cmd_arsenal(args.action, tool=args.tool)
    if args.group == "discoveries":
        return cmd_discoveries(args.file)
    return 2


if __name__ == "__main__":
    sys.exit(main())
