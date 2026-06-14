"""The engagement spine — the SOLE path to execution. Every action goes
resolve_class -> authorize -> gate -> (execute | enqueue) -> audit, fail-closed.
There is no other function in Grin that runs a command or writes an allow line."""
from dataclasses import dataclass
from datetime import datetime

from grin.audit import audit, result_digest
from grin.authorize import authorize
from grin.classes import resolve_class
from grin.engagement import Engagement, pending_path
from grin.gate import gate
from grin.pending import PendingStore
from grin.runner import ExecResult, Runner


@dataclass
class Outcome:
    status: str                       # executed | pending | refused
    reason: str = ""
    pending_id: str | None = None
    result: ExecResult | None = None
    record: dict | None = None


def _execute_and_audit(eng: Engagement, *, target, tool, command, action_class,
                       gated: bool, approved_by, runner: Runner) -> Outcome:
    res = runner.run(target, command, int(eng.env.get("timeout", 60)))
    rec = audit(eng.audit_log, engagement=eng.id, target=target, tool=tool,
                command=command, action_class=action_class, decision="allow",
                gated=gated, approved_by=approved_by, exit_code=res.exit_code,
                result_digest=result_digest(res.output), duration_s=res.duration_s)
    return Outcome(status="executed", result=res, record=rec)


def _audit_refuse(eng: Engagement, *, target, tool, command, action_class,
                  gated: bool, reason: str, approved_by=None) -> Outcome:
    rec = audit(eng.audit_log, engagement=eng.id, target=target, tool=tool,
                command=command, action_class=action_class, decision="refuse",
                gated=gated, approved_by=approved_by, reason=reason)
    return Outcome(status="refused", reason=reason, record=rec)


def _audit_unknown(eng: Engagement, *, pending_id: str, approver: str, verb: str) -> Outcome:
    rec = audit(eng.audit_log, engagement=eng.id, target="", tool="", command="",
                action_class="", decision="refuse", gated=True, approved_by=approver,
                reason=f"{verb} attempted for unknown pending id {pending_id!r}")
    return Outcome(status="refused", reason=f"no pending action {pending_id!r}", record=rec)


def submit_action(eng: Engagement, *, target: str, tool: str, command: str,
                  declared_class: str | None, runner: Runner, now: datetime) -> Outcome:
    action_class = resolve_class(tool, declared_class)

    decision = authorize(target, action_class, eng, now)
    if not decision.allowed:
        return _audit_refuse(eng, target=target, tool=tool, command=command,
                             action_class=action_class, gated=False, reason=decision.reason)

    store = PendingStore(pending_path(eng))
    if gate(action_class, eng.autonomy, store.approved_phases()) == "pending":
        pid = store.add(target=target, tool=tool, command=command, resolved_class=action_class)
        return Outcome(status="pending", pending_id=pid)

    return _execute_and_audit(eng, target=target, tool=tool, command=command,
                              action_class=action_class, gated=False, approved_by=None,
                              runner=runner)


def approve_action(eng: Engagement, pending_id: str, *, approver: str,
                   runner: Runner, now: datetime) -> Outcome:
    store = PendingStore(pending_path(eng))
    entry = store.peek(pending_id)
    if entry is None:
        return _audit_unknown(eng, pending_id=pending_id, approver=approver, verb="approve")

    # Re-authorize: time/state/scope may have changed since the action was queued.
    decision = authorize(entry["target"], entry["resolved_class"], eng, now)
    if not decision.allowed:
        # Leave the action in the pending queue — the block may be transient (e.g. an
        # out-of-window approval) — and audit the refused attempt. Not silently discarded.
        return _audit_refuse(eng, target=entry["target"], tool=entry["tool"],
                             command=entry["command"], action_class=entry["resolved_class"],
                             gated=True, reason=decision.reason, approved_by=approver)

    store.pop(pending_id)
    # phase-gated: approving an action opens that class's phase for the rest of the engagement.
    if eng.autonomy == "phase-gated":
        store.approve_phase(entry["resolved_class"])

    return _execute_and_audit(eng, target=entry["target"], tool=entry["tool"],
                              command=entry["command"], action_class=entry["resolved_class"],
                              gated=True, approved_by=approver, runner=runner)


def deny_action(eng: Engagement, pending_id: str, *, approver: str) -> Outcome:
    store = PendingStore(pending_path(eng))
    entry = store.pop(pending_id)
    if entry is None:
        return _audit_unknown(eng, pending_id=pending_id, approver=approver, verb="deny")
    return _audit_refuse(eng, target=entry["target"], tool=entry["tool"],
                         command=entry["command"], action_class=entry["resolved_class"],
                         gated=True, reason="operator denied", approved_by=approver)
