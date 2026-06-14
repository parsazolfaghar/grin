from grin.pending import PendingStore


def test_add_assigns_id_and_persists(tmp_path):
    path = str(tmp_path / "e.state.json")
    s = PendingStore(path)
    pid = s.add(target="t", tool="sqlmap", command="sqlmap -u t", resolved_class="exploit")
    assert pid
    s2 = PendingStore(path)
    entries = s2.list()
    assert len(entries) == 1
    assert entries[0]["id"] == pid
    assert entries[0]["tool"] == "sqlmap"
    assert entries[0]["resolved_class"] == "exploit"
    assert "ts" in entries[0]


def test_pop_removes_and_returns(tmp_path):
    path = str(tmp_path / "e.state.json")
    s = PendingStore(path)
    pid = s.add(target="t", tool="hydra", command="hydra ...", resolved_class="exploit")
    entry = s.pop(pid)
    assert entry["id"] == pid
    assert PendingStore(path).list() == []
    assert s.pop(pid) is None


def test_approve_phase_persists(tmp_path):
    path = str(tmp_path / "e.state.json")
    s = PendingStore(path)
    assert s.approved_phases() == set()
    s.approve_phase("exploit")
    assert PendingStore(path).approved_phases() == {"exploit"}


def test_missing_file_is_empty(tmp_path):
    s = PendingStore(str(tmp_path / "nope.state.json"))
    assert s.list() == []
    assert s.approved_phases() == set()


def test_peek_finds_without_removing(tmp_path):
    path = str(tmp_path / "e.state.json")
    s = PendingStore(path)
    pid = s.add(target="t", tool="nmap", command="c", resolved_class="active-scan")
    assert s.peek(pid)["id"] == pid
    assert len(s.list()) == 1     # peek does NOT remove
    assert s.peek("nope") is None
