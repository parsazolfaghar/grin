"""Permission-gated installer for the doctor's auto fixes. Nothing runs without confirm.
Advisory fixes are never executed (print-only). Each runner kind dispatches to an injected
executor returning (output, ok)."""
from dataclasses import dataclass


@dataclass(frozen=True)
class FixResult:
    fix: object        # the Fix
    applied: bool
    output: str
    ok: bool


def apply_fixes(fixes, *, confirm, run, ollama_pull=None, env_install=None) -> list:
    ollama_pull = ollama_pull or run
    env_install = env_install or run
    results = []
    for fix in fixes:
        if fix.kind != "auto":
            results.append(FixResult(fix, applied=False, output="(advisory — run it yourself)",
                                     ok=True))
            continue
        if not confirm(fix):
            results.append(FixResult(fix, applied=False, output="(declined)", ok=True))
            continue
        executor = {"ollama": ollama_pull, "env": env_install}.get(fix.runner, run)
        output, ok = executor(fix.command)
        results.append(FixResult(fix, applied=True, output=output, ok=ok))
    return results
