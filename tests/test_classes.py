from grin.classes import (
    ACTION_CLASSES, class_rank, resolve_class, UNKNOWN_FLOOR,
)


def test_classes_ordered_by_intrusiveness():
    assert ACTION_CLASSES == ("passive", "active-scan", "exploit", "post-exploit")
    assert class_rank("passive") < class_rank("exploit") < class_rank("post-exploit")


def test_known_tool_floor_overrides_lower_declared():
    assert resolve_class("sqlmap", "passive") == "exploit"
    assert resolve_class("hydra", "active-scan") == "exploit"


def test_declared_higher_than_floor_is_kept():
    assert resolve_class("nmap", "exploit") == "exploit"


def test_known_passive_tool_stays_passive():
    assert resolve_class("whois", "passive") == "passive"


def test_unknown_tool_floors_to_active_scan():
    assert UNKNOWN_FLOOR == "active-scan"
    assert resolve_class("some-random-tool", "passive") == "active-scan"
    assert resolve_class("some-random-tool", None) == "active-scan"


def test_invalid_declared_class_falls_back_to_floor():
    assert resolve_class("nmap", "banana") == "active-scan"
    assert resolve_class("sqlmap", "banana") == "exploit"


def test_tool_name_is_normalized():
    assert resolve_class("/usr/bin/SQLMap", "passive") == "exploit"
