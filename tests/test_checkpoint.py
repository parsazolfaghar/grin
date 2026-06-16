from collections import namedtuple
from grin.checkpoint import CHECKPOINT_DECISIONS, new_flags, route_queue
from grin.secret import Secret

Obj = namedtuple("Obj", "objective target")


def _flag(v):
    return Secret(label="flag", value=v, target="t", tool="x", command="c", context="ctx")


def test_decisions():
    assert CHECKPOINT_DECISIONS == ("sweep", "focus", "next", "stop")


def test_new_flags_filters_and_dedupes():
    secrets = [_flag("GRIN{a}"),
               Secret(label="SSH credentials", value="u:p", target="t", tool="hydra",
                      command="c", context="ctx"),
               _flag("GRIN{b}")]
    already = {"GRIN{a}"}
    assert new_flags(secrets, already) == ["GRIN{b}"]


def test_route_sweep_unchanged():
    q = [Obj("o1", "t1"), Obj("o2", "t2")]
    nq, focus, stop = route_queue("sweep", q, "t1")
    assert nq == q and focus is None and stop is False


def test_route_focus_keeps_only_target():
    q = [Obj("o1", "t1"), Obj("o2", "t2"), Obj("o3", "t1")]
    nq, focus, stop = route_queue("focus", q, "t1")
    assert [o.target for o in nq] == ["t1", "t1"] and focus == "t1" and stop is False


def test_route_next_drops_target():
    q = [Obj("o1", "t1"), Obj("o2", "t2")]
    nq, focus, stop = route_queue("next", q, "t1")
    assert [o.target for o in nq] == ["t2"] and focus is None and stop is False


def test_route_stop():
    nq, focus, stop = route_queue("stop", [Obj("o1", "t1")], "t1")
    assert nq == [] and stop is True


def test_route_unknown_is_sweep():
    q = [Obj("o1", "t1")]
    nq, focus, stop = route_queue("bogus", q, "t1")
    assert nq == q and stop is False
