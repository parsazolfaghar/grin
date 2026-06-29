from grin.assessbench.scorer import Score
from grin.assessbench.report import to_text, to_json


def _score(**kw):
    base = dict(target_id="demo", matched=(("g1", "f1"),), missed=("g2",),
                spurious=("bogus",), tp=1, fp=1, fn=1, precision=0.5, recall=0.5)
    base.update(kw)
    return Score(**base)


def test_to_json_shape_is_stable_and_serializable():
    import json
    j = to_json(_score())
    assert j["target_id"] == "demo"
    assert (j["tp"], j["fp"], j["fn"]) == (1, 1, 1)
    assert j["precision"] == 0.5 and j["recall"] == 0.5
    assert j["matched"] == [["g1", "f1"]]
    assert j["missed"] == ["g2"]
    assert j["spurious"] == ["bogus"]
    json.dumps(j)   # must be JSON-serializable (no tuples leaking)


def test_to_text_shows_metrics_and_breakdown():
    t = to_text(_score())
    assert "demo" in t
    assert "precision" in t.lower() and "recall" in t.lower()
    assert "0.50" in t
    assert "g1" in t and "f1" in t   # matched
    assert "g2" in t                  # missed
    assert "bogus" in t               # spurious


def test_to_text_perfect_score():
    s = _score(matched=(("g1", "f1"),), missed=(), spurious=(),
               tp=1, fp=0, fn=0, precision=1.0, recall=1.0)
    t = to_text(s)
    assert "1.00" in t
    # clean run: no false-positive section header
    assert "spurious" not in t.lower()
