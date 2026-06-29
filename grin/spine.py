"""The engagement spine — the SOLE path to execution. Every action goes
resolve_class -> authorize -> gate -> (execute | enqueue) -> audit, fail-closed.
There is no other function in Grin that runs a command or writes an allow line."""
import os
from dataclasses import dataclass
from datetime import datetime

from grin.audit import audit, result_digest
from grin.authorize import authorize
from grin.classes import resolve_class
from grin.engagement import Engagement, pending_path
from grin.gate import gate
from grin.pending import PendingStore
from grin.runner import ExecResult, Runner
from grin.safety import is_self_destructive, destructive_allowed
from grin.stealth import profile_for, apply as apply_stealth


@dataclass
class Outcome:
    status: str                       # executed | pending | refused
    reason: str = ""
    pending_id: str | None = None
    result: ExecResult | None = None
    record: dict | None = None


def _execute_and_audit(eng: Engagement, *, target, tool, command, action_class,
                       gated: bool, approved_by, runner: Runner) -> Outcome:
    # R3 self-guard: block commands that would destroy the OPERATOR's own host/disk (never offensive
    # actions against the target). Override with GRIN_ALLOW_DESTRUCTIVE=1. Audited as a refusal.
    if is_self_destructive(command) and not destructive_allowed():
        return _audit_refuse(eng, target=target, tool=tool, command=command,
                             action_class=action_class, gated=gated, approved_by=approved_by,
                             reason="blocked: self-destructive command (R3 self-guard); "
                                    "set GRIN_ALLOW_DESTRUCTIVE=1 to override")
    profile = profile_for(eng.stealth, os.environ, seed=eng.id)
    command = apply_stealth(profile, tool, command)
    stealth_level = eng.stealth if eng.stealth != "off" else None
    res = runner.run(target, command, int(eng.env.get("timeout", 60)))
    rec = audit(eng.audit_log, engagement=eng.id, target=target, tool=tool,
                command=command, action_class=action_class, decision="allow",
                gated=gated, approved_by=approved_by, exit_code=res.exit_code,
                result_digest=result_digest(res.output), duration_s=res.duration_s,
                stealth=stealth_level)
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

    # Defense in depth: even with an in-scope target, refuse a command that names an out-of-scope
    # host/CIDR (e.g. a subnet sweep `nmap -sn 192.168.1.0/24` while scope is a single host). The
    # target check above only sees the target field; this catches hosts smuggled into the command.
    from grin.scope import command_out_of_scope
    oos = command_out_of_scope(command, eng.scope.include, eng.scope.exclude)
    if oos:
        return _audit_refuse(eng, target=target, tool=tool, command=command,
                             action_class=action_class, gated=False,
                             reason=f"command targets out-of-scope host(s): {', '.join(oos)}")

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


def apply_device_stealth(eng: Engagement, *, runner: Runner, iface: str = "eth0") -> list:
    """Run the engagement's device-spoof setup (MAC/hostname) once, where it bites. Best-effort: a
    failed step is audited and does NOT abort the engagement. No-op (returns []) off / behind NAT."""
    import shutil
    from grin.platform_info import host_has_arsenal
    from grin.stealth import profile_for, device_setup, can_spoof_device
    profile = profile_for(eng.stealth, os.environ, seed=eng.id)
    caps = can_spoof_device(host_has_arsenal, shutil.which)
    cmds = device_setup(profile, iface=iface, can_spoof=caps)
    recs = []
    for c in cmds:
        # Defense in depth: this is a second execution path outside submit_action's gate, so honor
        # the same R3 self-destructive guard here — a device-setup command is never destructive in
        # normal use, but we never run one that is unless destructive ops are explicitly allowed.
        if is_self_destructive(c) and not destructive_allowed():
            recs.append(audit(eng.audit_log, engagement=eng.id, target="localhost", tool=c.split()[0],
                              command=c, action_class="passive", decision="block", gated=True,
                              exit_code=None, reason="self-destructive-blocked", stealth=eng.stealth))
            continue
        res = runner.run("localhost", c, int(eng.env.get("timeout", 60)))
        rec = audit(eng.audit_log, engagement=eng.id, target="localhost", tool=c.split()[0],
                    command=c, action_class="passive", decision="allow", gated=False,
                    exit_code=res.exit_code, reason="stealth-device-setup", stealth=eng.stealth)
        recs.append(rec)
    return recs
