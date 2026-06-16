from grin.runner import ArsenalRunner, build_runner, DEFAULT_ARSENALS


class _FakeContainer:
    def __init__(self, tools):
        self._tools = tools
    def exec_run(self, cmd, demux=False):
        shell = cmd[-1]
        if shell.startswith("command -v "):
            tool = shell.split("command -v ", 1)[1].strip()
            return (0, b"/usr/bin/x") if tool in self._tools else (1, b"")
        return (0, b"RAN")


class _Containers:
    def __init__(self, m):
        self._m = m
    def get(self, name):
        return self._m[name]


class _FakeClient:
    def __init__(self, m):
        self.containers = _Containers(m)


def _cli(m):
    return _FakeClient(m)


def test_routes_to_container_with_tool():
    cli = _cli({"grin-kali": _FakeContainer({"nmap"}),
                "grin-blackarch": _FakeContainer({"special"})})
    r = ArsenalRunner(containers=("grin-kali", "grin-blackarch"), client=cli)
    out = r.run("10.0.0.1", "nmap -sV 10.0.0.1")
    assert out.exit_code == 0 and out.output == "RAN"
    assert r.run("10.0.0.1", "special --x").output == "RAN"


def test_missing_tool_reports_clearly():
    cli = _cli({"grin-kali": _FakeContainer(set()), "grin-blackarch": _FakeContainer(set())})
    r = ArsenalRunner(containers=("grin-kali", "grin-blackarch"), client=cli)
    out = r.run("10.0.0.1", "obscuretool --x")
    assert out.exit_code != 0 and "arsenal add" in out.output


def test_resolution_cached():
    cli = _cli({"grin-kali": _FakeContainer({"nmap"}), "grin-blackarch": _FakeContainer(set())})
    r = ArsenalRunner(containers=("grin-kali", "grin-blackarch"), client=cli)
    r.run("t", "nmap -sV t")
    assert r._cache.get("nmap") == "grin-kali"


def test_build_runner_arsenal():
    runner = build_runner({"kind": "arsenal"})
    assert isinstance(runner, ArsenalRunner)
    assert tuple(runner._containers) == DEFAULT_ARSENALS
