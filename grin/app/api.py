"""GrinApi — the Python<->JS bridge exposed to the pywebview UI. Every method returns
JSON-serializable data (never raises across the bridge — failures come back as {"error": ...}).
The app adds NO execution path: actions route through the existing spine/orchestrator. All
collaborators are injectable so the bridge is unit-tested with fakes (no pywebview/Ollama)."""
import glob
import json
import os
import uuid
from datetime import datetime

from grin.engagement import load_engagement, EngagementError, pending_path
from grin.inference import OllamaClient
from grin.platform_info import detect_platform
from grin.doctor import run_doctor
from grin.report_store import load_result, result_path, save_result
from grin.loot import LootStore, loot_dir
from grin.pending import PendingStore
from grin.runner import build_runner
from grin.spine import approve_action, deny_action
from grin.executor import DEFAULT_MODEL
from grin.app.serialize import to_jsonable
from grin.app.runner_thread import JobRunner


class GrinApi:
    def __init__(self, *, engagements_dir=".", ollama=None, runner_factory=build_runner,
                 approve_fn=approve_action, deny_fn=deny_action, now_fn=datetime.now,
                 job_runner_factory=None):
        self.engagements_dir = engagements_dir
        self._ollama = ollama or OllamaClient()
        self._runner_factory = runner_factory
        self._approve = approve_fn
        self._deny = deny_fn
        self._now = now_fn
        self._jobs = {}
        # set lazily to avoid an import cycle at module load; real default wired in launch.py
        self._job_runner_factory = job_runner_factory

    # ---- helpers ----
    def _load(self, file):
        return load_engagement(file)

    def _who(self):
        import getpass
        try:
            return getpass.getuser()
        except Exception:  # noqa: BLE001
            return "operator"

    # ---- read-only views ----
    def list_engagements(self):
        rows = []
        for path in sorted(glob.glob(os.path.join(self.engagements_dir, "*.yaml"))):
            try:
                e = self._load(path)
                rows.append({"valid": True, "file": path, "id": e.id, "name": e.name,
                             "mode": e.mode, "autonomy": e.autonomy, "state": e.state,
                             "targets": len(e.scope.include), "audit_log": e.audit_log})
            except (EngagementError, OSError) as ex:
                rows.append({"valid": False, "file": path, "error": str(ex)})
        return rows

    def doctor(self, file=None, models=None, tools=None):
        try:
            plat = detect_platform()
            eng = self._load(file) if file else None
            runner = self._runner_factory(eng.env) if eng else None
            required = models or [DEFAULT_MODEL]
            tool_list = tools or ["nmap"]
            rep = run_doctor(platform=plat, ollama=self._ollama, engagement=eng, runner=runner,
                             required_models=required, tools=tool_list)
            return {"platform": {"os": plat.os, "pkg_mgr": plat.host_pkg_mgr},
                    "checks": [to_jsonable(c) for c in rep.checks], "ok": rep.ok}
        except Exception as ex:  # noqa: BLE001
            return {"error": str(ex)}

    def findings(self, file):
        try:
            eng = self._load(file)
            res = load_result(result_path(eng))
            return [to_jsonable(f) for f in res.findings]
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return []
        except EngagementError as ex:
            return {"error": str(ex)}

    def loot(self, file):
        try:
            eng = self._load(file)
            return LootStore(loot_dir(eng)).all()
        except EngagementError as ex:
            return {"error": str(ex)}

    def audit(self, file, limit=50):
        try:
            eng = self._load(file)
            if not os.path.exists(eng.audit_log):
                return []
            with open(eng.audit_log) as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
            out = []
            for ln in lines[-limit:]:
                try:
                    out.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
            return out
        except EngagementError as ex:
            return {"error": str(ex)}

    def blocked(self, file):
        try:
            eng = self._load(file)
            return PendingStore(pending_path(eng)).list()
        except EngagementError as ex:
            return {"error": str(ex)}

    # ---- actions (route through the existing spine/orchestrator; no new execution path) ----
    def approve(self, file, pending_id):
        try:
            eng = self._load(file)
            runner = self._runner_factory(eng.env)
            out = self._approve(eng, pending_id, approver=self._who(), runner=runner,
                                now=self._now())
            return {"status": out.status, "reason": out.reason}
        except Exception as ex:  # noqa: BLE001
            return {"error": str(ex)}

    def deny(self, file, pending_id):
        try:
            eng = self._load(file)
            out = self._deny(eng, pending_id, approver=self._who())
            return {"status": out.status, "reason": out.reason}
        except Exception as ex:  # noqa: BLE001
            return {"error": str(ex)}

    def start_engagement(self, file, goal, **opts):
        try:
            eng = self._load(file)
        except Exception as ex:  # noqa: BLE001
            return {"error": str(ex)}
        job_id = uuid.uuid4().hex[:12]
        if self._job_runner_factory is not None:
            job = self._job_runner_factory(eng, goal=goal, **opts)
        else:
            from grin.cli import _make_client, _make_executor_client
            job = JobRunner(
                eng, goal=goal, orchestrate_fn=_default_orchestrate(), save_fn=save_result_for,
                snapshot_reader=lambda e: self._merged_snapshot(file),
                client_factory=_make_client, executor_factory=_make_executor_client,
                runner_factory=self._runner_factory, now_fn=self._now, opts=opts)
        job.start()
        self._jobs[job_id] = (file, job)
        return {"job_id": job_id, "started": True}

    def engagement_state(self, job_id):
        entry = self._jobs.get(job_id)
        if entry is None:
            return {"error": f"unknown job {job_id!r}"}
        _file, job = entry
        return job.snapshot()

    def _merged_snapshot(self, file):
        return {"objectives": [], "findings": self.findings(file), "audit": self.audit(file),
                "blocked": self.blocked(file)}


def save_result_for(eng, res):
    from grin.report_store import save_result, result_path
    save_result(result_path(eng), res)


def _default_orchestrate():
    from grin.orchestrator import orchestrate
    return orchestrate
