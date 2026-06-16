from grin.installer import apply_fixes
from grin.doctor import Fix

def _auto(runner="ollama", cmd="ollama pull x"):
    return Fix(label="pull x", command=cmd, kind="auto", runner=runner)

def test_advisory_never_runs():
    calls = []
    adv = Fix("start", "ollama serve", "advisory", "host")
    results = apply_fixes([adv], confirm=lambda f: True, run=lambda c: calls.append(c))
    assert calls == []
    assert results[0].applied is False and results[0].ok is True

def test_auto_runs_only_when_confirmed():
    calls = []
    res = apply_fixes([_auto(runner="pip", cmd="pip install httpx")],
                      confirm=lambda f: False, run=lambda c: calls.append(c) or ("", True))
    assert calls == [] and res[0].applied is False

def test_auto_confirmed_dispatches_to_pip_runner():
    seen = {}
    def run(cmd): seen["run"] = cmd; return ("ok", True)
    res = apply_fixes([_auto(runner="pip", cmd="pip install httpx")],
                      confirm=lambda f: True, run=run)
    assert seen["run"] == "pip install httpx"
    assert res[0].applied is True and res[0].ok is True

def test_ollama_and_env_use_their_executors():
    log = []
    res = apply_fixes(
        [_auto(runner="ollama", cmd="ollama pull m"),
         Fix("install nmap", "apt-get install -y nmap", "auto", "env")],
        confirm=lambda f: True,
        run=lambda c: ("host", True),
        ollama_pull=lambda c: (log.append(("ollama", c)) or ("pulled", True)),
        env_install=lambda c: (log.append(("env", c)) or ("installed", True)))
    assert ("ollama", "ollama pull m") in log
    assert ("env", "apt-get install -y nmap") in log
    assert all(r.ok for r in res)

def test_failing_executor_marks_not_ok_and_continues():
    res = apply_fixes(
        [_auto(runner="pip", cmd="bad"), _auto(runner="pip", cmd="good")],
        confirm=lambda f: True,
        run=lambda c: ("boom", False) if c == "bad" else ("done", True))
    assert res[0].ok is False and res[1].ok is True
