"""GrinApi — the Python<->JS bridge exposed to the pywebview UI. Every method returns
JSON-serializable data (never raises across the bridge — failures come back as {"error": ...}).
The app adds NO execution path: actions route through the existing spine/orchestrator. All
collaborators are injectable so the bridge is unit-tested with fakes (no pywebview/Ollama)."""
import glob
import json
import os
import re
import uuid
from datetime import datetime

from grin.checkpoint import CHECKPOINT_DECISIONS
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
from grin.intent import parse_intent
from grin.manual import manual_for, allowed_actions_for
from grin.adhoc import build_adhoc_engagement
from grin.strength import strength_params
from grin.toolrequest import ToolRequestStore, tool_requests_path
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
        self._tool_env = None   # active deployment profile's tool env (None -> use the engagement's)
        self._stealth = "off"
        self._strength = "normal"
        self._tool_acquire = "ask"

    def set_stealth(self, level):
        """Set the stealth level applied to app-launched (ad-hoc) engagements (off|quiet|paranoid)."""
        self._stealth = level

    def set_strength(self, level):
        """Set the attack-strength level for app-launched (ad-hoc) engagements."""
        self._strength = level

    def set_tool_acquire(self, level):
        """Policy for installing missing tools on app-launched engagements (ask|auto|never)."""
        self._tool_acquire = level

    def set_backend(self, tool_env):
        """Apply a deployment profile's backend: rebuild the Ollama client (re-reads
        $GRIN_OLLAMA_URL, already set by config.apply_profile) and set the tool-env override that
        app-launched engagements run in. Inference + tools rewired together (roadmap R4)."""
        self._tool_env = tool_env
        self._ollama = OllamaClient()

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

    def clear_engagements(self):
        """Delete auto-generated ad-hoc engagements (adhoc-*) + their audit/tool siblings from the
        engagements dir. Hand-written / sample engagements are left untouched. Never raises."""
        try:
            cleared = 0
            for path in glob.glob(os.path.join(self.engagements_dir, "adhoc-*.yaml")):
                base = path[:-len(".yaml")]
                for f in (path, base + ".jsonl", base + ".tools.json"):
                    try:
                        os.remove(f)
                    except OSError:
                        pass
                cleared += 1
            return {"cleared": cleared}
        except Exception as ex:  # noqa: BLE001 - never raise across the bridge
            return {"error": str(ex)}

    def doctor(self, file=None, models=None, tools=None):
        try:
            plat = detect_platform()
            eng = self._load(file) if file else None
            runner = self._runner_factory(eng.env) if eng else None
            required = models or [DEFAULT_MODEL]
            tool_list = tools or ["nmap"]
            from grin.inference import active_backend
            # check the ACTIVE brain (cloud when configured) — not always Ollama, which would show
            # a misleading amber for cloud users with no local Ollama running
            rep = run_doctor(platform=plat, ollama=self._ollama, engagement=eng, runner=runner,
                             required_models=required, tools=tool_list, backend=active_backend())
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
        except Exception as ex:  # noqa: BLE001 - never raise across the bridge
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
        except Exception as ex:  # noqa: BLE001 - never raise across the bridge
            return {"error": str(ex)}

    def blocked(self, file):
        try:
            eng = self._load(file)
            return PendingStore(pending_path(eng)).list()
        except Exception as ex:  # noqa: BLE001 - never raise across the bridge
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

    def pending_tools(self, file):
        """Tools this engagement needs that await Allow/Deny. Never raises across the bridge."""
        try:
            return ToolRequestStore(tool_requests_path(self._load(file))).requested()
        except Exception as ex:  # noqa: BLE001
            return {"error": str(ex)}

    def approve_tool(self, file, tool):
        """Install a requested tool into the arsenal, audit it, mark it resolved."""
        try:
            from grin.arsenal import run_add
            from grin.audit import audit
            # tool is interpolated into a docker-exec shell command by run_add — only allow a real
            # package-name charset so a crafted tool token can't inject shell into the container
            if not re.fullmatch(r"[A-Za-z0-9_.+-]+", tool or ""):
                return {"error": f"refusing unsafe tool name {tool!r}"}
            eng = self._load(file)
            rc = run_add(tool)
            if rc != 0:
                return {"error": f"install failed for {tool!r}"}
            ToolRequestStore(tool_requests_path(eng)).resolve(tool)
            audit(eng.audit_log, engagement=eng.id, target="", tool=tool,
                  command=f"arsenal add {tool}", action_class="passive", decision="allow",
                  gated=False, approved_by=self._who(), reason="tool-install")
            return {"status": "installed", "tool": tool}
        except Exception as ex:  # noqa: BLE001
            return {"error": str(ex)}

    def deny_tool(self, file, tool):
        """Deny a tool request; audit it."""
        try:
            from grin.audit import audit
            eng = self._load(file)
            ToolRequestStore(tool_requests_path(eng)).deny(tool)
            audit(eng.audit_log, engagement=eng.id, target="", tool=tool, command="",
                  action_class="passive", decision="refuse", gated=False,
                  approved_by=self._who(), reason="tool-deny")
            return {"status": "denied", "tool": tool}
        except Exception as ex:  # noqa: BLE001
            return {"error": str(ex)}

    def start_engagement(self, file, goal, **opts):
        try:
            eng = self._load(file)
        except Exception as ex:  # noqa: BLE001
            return {"error": str(ex)}
        job_id = uuid.uuid4().hex[:12]
        if self._job_runner_factory is not None:
            job = self._job_runner_factory(eng, goal=goal, env=self._tool_env, **opts)
        else:
            from grin.cli import _make_client, _make_executor_client
            # mirror the CLI: orchestrate needs the engagement file path so sub-tasks write
            # their journals/results next to it (the app adds no execution path of its own).
            run_opts = {"engagement_path": file, **opts}
            job = JobRunner(
                eng, goal=goal, orchestrate_fn=_default_orchestrate(), save_fn=save_result_for,
                snapshot_reader=lambda e: self._merged_snapshot(file),
                client_factory=_make_client, executor_factory=_make_executor_client,
                runner_factory=self._runner_factory, now_fn=self._now, opts=run_opts,
                env=self._tool_env)
        job.start()
        self._jobs[job_id] = (file, job)
        return {"job_id": job_id, "started": True}

    def interpret(self, text):
        """Parse free text -> {goal, targets, target_type, bare_target, can_engage, allowed_actions,
        manual}. Used for the live preview as the operator types. Never raises across the bridge."""
        try:
            intent = parse_intent(text, client=self._ollama, model=DEFAULT_MODEL)
            cat = _catalog() or []
            man = manual_for(intent.target_type, cat)
            return {
                "goal": intent.goal, "targets": intent.targets,
                "target_type": intent.target_type, "bare_target": intent.bare_target,
                "can_engage": bool(intent.targets),
                "allowed_actions": allowed_actions_for(intent.target_type),
                "manual": {"header": man.header,
                           "sections": [{"tactic": s.tactic, "items": s.items}
                                        for s in man.sections]},
            }
        except Exception as ex:  # noqa: BLE001 - never raise across the bridge
            return {"error": str(ex)}

    def engage_text(self, text):
        """Build a scope-locked ad-hoc engagement from free text and start it (aggression/budgets per
        the strength level). Reuses start_engagement — no new execution path. Never raises across the bridge."""
        try:
            intent = parse_intent(text, client=self._ollama, model=DEFAULT_MODEL)
            if not intent.targets:
                return {"error": "no target found in prompt"}
            eng, path = build_adhoc_engagement(
                intent, now=self._now(), operator=self._who(),
                stealth=self._stealth, strength=self._strength,
                tool_acquire=self._tool_acquire)
            params = strength_params(self._strength)
            opts = {"aggressive": params.aggressive,
                    "max_objectives": params.max_objectives,
                    "max_steps": params.max_steps}
            if params.aggressive:
                cat = _catalog()
                if cat is not None:
                    opts["catalog"] = cat
            res = self.start_engagement(path, intent.goal, **opts)
            if isinstance(res, dict) and "error" not in res:
                res["file"] = path   # let the GUI bind to this engagement (tool prompts, etc.)
            return res
        except Exception as ex:  # noqa: BLE001 - never raise across the bridge
            return {"error": str(ex)}

    def engagement_state(self, job_id):
        entry = self._jobs.get(job_id)
        if entry is None:
            return {"error": f"unknown job {job_id!r}"}
        _file, job = entry
        return job.snapshot()

    def resolve_checkpoint(self, job_id, decision):
        """Answer a pending aggressive checkpoint (sweep|focus|next|stop). Never raises across the bridge."""
        try:
            if decision not in CHECKPOINT_DECISIONS:
                return {"error": f"invalid decision {decision!r}"}
            entry = self._jobs.get(job_id)
            if entry is None:
                return {"error": f"unknown job {job_id!r}"}
            entry[1].resolve(decision)
            return {"status": "resumed", "decision": decision}
        except Exception as ex:  # noqa: BLE001
            return {"error": str(ex)}

    def stop_engagement(self, job_id):
        """Operator Stop: cooperatively end a running engagement (the loop stops between objectives).
        Never raises across the bridge."""
        try:
            entry = self._jobs.get(job_id)
            if entry is None:
                return {"error": f"unknown job {job_id!r}"}
            entry[1].cancel()
            return {"status": "stopping"}
        except Exception as ex:  # noqa: BLE001
            return {"error": str(ex)}

    def _merged_snapshot(self, file):
        return {"objectives": [], "findings": self.findings(file), "audit": self.audit(file),
                "blocked": self.blocked(file)}


def _catalog():
    """Load the ATT&CK catalog for the manual / aggressive runs; None if unreadable."""
    from grin.cli import _load_catalog_or_none
    return _load_catalog_or_none()


def save_result_for(eng, res):
    from grin.report_store import result_path
    save_result(result_path(eng), res)


def _default_orchestrate():
    from grin.orchestrator import orchestrate
    return orchestrate
