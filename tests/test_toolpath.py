from grin.toolpath import ensure_tool_path


def test_prepends_existing_dirs():
    env = {"PATH": "/usr/bin:/bin"}
    added = ensure_tool_path(env, exists=lambda d: d in ("/opt/homebrew/bin", "/usr/local/bin"))
    assert added == ["/opt/homebrew/bin", "/usr/local/bin"]
    assert env["PATH"].startswith("/opt/homebrew/bin:/usr/local/bin:")
    assert env["PATH"].endswith("/usr/bin:/bin")


def test_no_duplicates():
    env = {"PATH": "/opt/homebrew/bin:/usr/bin"}
    added = ensure_tool_path(env, exists=lambda d: d == "/opt/homebrew/bin")
    assert added == [] and env["PATH"] == "/opt/homebrew/bin:/usr/bin"


def test_empty_path():
    env = {}
    ensure_tool_path(env, exists=lambda d: d == "/usr/local/bin")
    assert env["PATH"] == "/usr/local/bin"


def test_none_added_when_nothing_exists():
    env = {"PATH": "/usr/bin"}
    assert ensure_tool_path(env, exists=lambda d: False) == [] and env["PATH"] == "/usr/bin"
