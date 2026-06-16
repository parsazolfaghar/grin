from grin.catalog import load_catalog
from grin.cli import DEFAULT_CATALOG_PATH
from grin.manual import manual_for, allowed_actions_for, header_for, Manual


def _cat():
    return load_catalog(DEFAULT_CATALOG_PATH)


def test_allowed_actions_table():
    assert allowed_actions_for("web-url") == ["passive", "active-scan", "exploit", "post-exploit"]
    assert allowed_actions_for("ip-host") == ["passive", "active-scan", "exploit", "post-exploit"]
    assert allowed_actions_for("unknown") == ["passive", "active-scan"]


def test_manual_for_web_lists_techniques_grouped_by_tactic():
    m = manual_for("web-url", _cat())
    assert isinstance(m, Manual)
    assert m.target_type == "web-url"
    tactics = [s.tactic for s in m.sections]
    assert "reconnaissance" in tactics
    names = [item for s in m.sections for item in s.items]
    assert any("Exploit Public-Facing Application" in n for n in names)
    assert any("nmap" in n for n in names)


def test_manual_for_unknown_is_always_only():
    m = manual_for("unknown", _cat())
    names = [item for s in m.sections for item in s.items]
    assert not any("Brute Force" in n for n in names)
    assert any("Active Scanning" in n for n in names)


def test_header_for_returns_sentence():
    assert "web" in header_for("web-url").lower()
    assert header_for("unknown")
