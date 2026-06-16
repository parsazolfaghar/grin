from grin.doctor import check_arsenal


def test_arsenal_ok_when_all_present():
    present = {"grin-kali": True, "grin-blackarch": True}
    checks = check_arsenal(("grin-kali", "grin-blackarch"), running_probe=lambda c: present[c])
    assert all(c.status == "ok" for c in checks)
    assert len(checks) == 2


def test_arsenal_missing_flagged():
    present = {"grin-kali": True, "grin-blackarch": False}
    checks = check_arsenal(("grin-kali", "grin-blackarch"), running_probe=lambda c: present[c])
    by = {c.name: c for c in checks}
    assert by["arsenal: grin-kali"].status == "ok"
    assert by["arsenal: grin-blackarch"].status in ("broken", "missing")
