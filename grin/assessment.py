"""Deterministic assessment sweep — fire the known-class probes directly instead of relying on the
LLM to run them.

The autonomous loop kept varying on WHETHER (and HOW) it ran each probe — one run fumbled the
idor-probe invocation, the next skipped it entirely. But the probes are deterministic, so their
detection should not depend on LLM whim. The sweep runs every pre-built command and extracts its
findings; the LLM loop then reasons on top (novel leads, vulns without a dedicated probe)."""
from grin.prompts import assessment_commands
from grin.extractors import extract_findings


def assessment_sweep(base_url, credentials, run_action, target):
    """run_action(tool, command) -> stdout string. Returns the Findings from every pre-built probe
    for this target. Empty base_url -> no commands -> []."""
    findings = []
    for command in assessment_commands(base_url, credentials):
        tool = command.split()[0]
        output = run_action(tool, command) or ""
        findings.extend(extract_findings(tool, command, output, target))
    return findings
