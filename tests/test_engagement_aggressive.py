from grin.engagement import validate_engagement


def _base(extra=None):
    d = {"id": "e", "name": "n", "mode": "own-lab",
         "scope": {"in": ["127.0.0.1"], "exclude": []},
         "roe": {"allowed_actions": ["active-scan"], "windows": []},
         "autonomy": "autonomous", "env": {"kind": "local"},
         "audit_log": "./a.jsonl", "state": "active"}
    if extra:
        d.update(extra)
    return d


def test_aggressive_defaults_false():
    eng = validate_engagement(_base())
    assert eng.aggressive is False


def test_aggressive_true_parsed():
    eng = validate_engagement(_base({"aggressive": True}))
    assert eng.aggressive is True
