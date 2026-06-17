from grin.lab.answers import load_answers

ALL_IDS = {"t1-ssh", "t2-web", "t3-chain", "t4-crack", "t5-ssti", "t6-pivot"}


def test_render_answers_uses_supplied_flags(tmp_path):
    from lab.build import render_answers
    flags = {i: f"GRIN{{{i}}}" for i in ALL_IDS}
    out = tmp_path / "answers.yaml"
    render_answers(flags, str(out))
    targets = load_answers(str(out))
    got = {t.id: t.flag for t in targets}
    assert got == flags
    by = {t.id: t for t in targets}
    assert by["t1-ssh"].ip == "172.30.0.11" and by["t1-ssh"].open_ports == [22]
    assert by["t2-web"].vuln_class == "command-injection"
    assert by["t3-chain"].tier == "hard"
    # T4-T6 are the harder tier; T6 carries an extra in-scope pivot host.
    assert by["t4-crack"].tier == "expert" and 22 in by["t4-crack"].open_ports
    assert by["t5-ssti"].tier == "elite"
    assert by["t6-pivot"].tier == "master"
    assert by["t6-pivot"].extra_scope == ["172.30.0.17"]


def test_new_flags_are_unique_grin_format():
    from lab.build import new_flags
    f = new_flags()
    assert set(f) == ALL_IDS
    assert all(v.startswith("GRIN{") and v.endswith("}") for v in f.values())
    assert len(set(f.values())) == len(ALL_IDS)
