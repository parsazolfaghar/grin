from grin.lab.answers import load_answers


def test_render_answers_uses_supplied_flags(tmp_path):
    from lab.build import render_answers
    flags = {"t1-ssh": "GRIN{aaa}", "t2-web": "GRIN{bbb}", "t3-chain": "GRIN{ccc}"}
    out = tmp_path / "answers.yaml"
    render_answers(flags, str(out))
    targets = load_answers(str(out))
    got = {t.id: t.flag for t in targets}
    assert got == flags
    by = {t.id: t for t in targets}
    assert by["t1-ssh"].ip == "172.30.0.11" and by["t1-ssh"].open_ports == [22]
    assert by["t2-web"].vuln_class == "command-injection"
    assert by["t3-chain"].tier == "hard"


def test_new_flags_are_unique_grin_format():
    from lab.build import new_flags
    f = new_flags()
    assert set(f) == {"t1-ssh", "t2-web", "t3-chain"}
    assert all(v.startswith("GRIN{") and v.endswith("}") for v in f.values())
    assert len(set(f.values())) == 3
