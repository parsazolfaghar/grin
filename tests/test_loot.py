import json
from grin.secret import Secret
from grin.loot import loot_dir, LootStore
from grin.engagement import validate_engagement

ENG = validate_engagement({
    "id": "e1", "name": "n", "mode": "client", "scope": {"in": ["*.acme.test"]},
    "roe": {"allowed_actions": ["exploit"]}, "autonomy": "autonomous",
    "env": {"kind": "local"}, "audit_log": "./audit/e1.jsonl", "state": "active"})


def test_loot_dir_from_audit_log():
    assert loot_dir(ENG) == "./audit/e1.loot"


def test_record_writes_jsonl_and_md(tmp_path):
    d = str(tmp_path / "e1.loot")
    s = Secret(label="WordPress admin credential", value="admin:hunter2",
               target="www.acme.test", tool="hydra", command="hydra ...",
               context="grants wp-admin")
    LootStore(d).record(s, objective="brute the login")
    rows = LootStore(d).all()
    assert len(rows) == 1
    assert rows[0]["label"] == "WordPress admin credential"
    assert rows[0]["value"] == "admin:hunter2"
    assert rows[0]["objective"] == "brute the login"
    assert "ts" in rows[0]
    md = open(f"{d}/secrets.md").read()
    assert "WordPress admin credential" in md and "admin:hunter2" in md and "hydra" in md


def test_all_empty_when_absent(tmp_path):
    assert LootStore(str(tmp_path / "nope.loot")).all() == []
