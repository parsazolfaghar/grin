from grin.labbench.scorers import RunScore
from grin.labbench.report import aggregate, ModelAgg, to_text


def _rs(tid, flag, recall, refusals=0, invalid=0, dur=10.0):
    return RunScore(tid, flag, recall, refusals, invalid, dur)


def test_aggregate_groups_by_role_model():
    rows = [
        ("exploit", "A", _rs("t1", True, 1.0, dur=5)),
        ("exploit", "A", _rs("t2", True, 1.0, dur=7)),
        ("exploit", "B", _rs("t1", False, 0.0, dur=9)),
        ("exploit", "B", _rs("t2", False, 0.5, dur=11)),
    ]
    aggs = aggregate(rows)
    a = next(x for x in aggs if x.model == "A")
    b = next(x for x in aggs if x.model == "B")
    assert a.flag_rate == 1.0 and b.flag_rate == 0.0
    assert a.mean_recall == 1.0 and b.mean_recall == 0.25
    assert a.median_time == 6.0


def test_aggregate_refusal_is_fatal_in_ranking():
    rows = [
        ("exploit", "Good", _rs("t1", True, 1.0)),
        ("exploit", "Refuser", _rs("t1", True, 1.0, refusals=2)),
    ]
    aggs = aggregate(rows)
    ranked = [a.model for a in aggs if a.role == "exploit"]
    assert ranked[0] == "Good" and ranked[-1] == "Refuser"


def test_to_text_mentions_winner_and_no_tables():
    rows = [("exploit", "A", _rs("t1", True, 1.0)),
            ("exploit", "B", _rs("t1", False, 0.0))]
    txt = to_text(aggregate(rows))
    assert "exploit" in txt and "A" in txt
    assert "|" not in txt
