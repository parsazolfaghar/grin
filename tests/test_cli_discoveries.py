from grin.cli import main
from grin.engagement import load_engagement
from grin.results import ResultStore, results_path

ENG_YAML = """
id: e2
name: disc-test
mode: own-lab
scope:
  in: ["10.0.0.0/24"]
roe:
  allowed_actions: [passive, active-scan]
autonomy: autonomous
env: {{kind: local}}
audit_log: {audit}
state: active
"""


def _write_eng(tmp_path):
    audit = str(tmp_path / "audit" / "e2.jsonl")
    p = tmp_path / "e2.yaml"
    p.write_text(ENG_YAML.format(audit=audit))
    return str(p)


def test_discoveries_subcommand_parses():
    from grin.cli import build_parser
    args = build_parser().parse_args(["discoveries", "e.yaml"])
    assert args.group == "discoveries"
    assert args.file == "e.yaml"


def test_cmd_discoveries_no_results(tmp_path, capsys):
    path = _write_eng(tmp_path)
    rc = main(["discoveries", path])
    assert rc == 0
    out = capsys.readouterr().out
    assert "no discoveries yet" in out


def test_cmd_discoveries_shows_hosts(tmp_path, capsys):
    path = _write_eng(tmp_path)
    eng = load_engagement(path)
    ResultStore(results_path(eng)).put(
        id="r1", command="nmap 10.0.0.5",
        output="22/tcp open ssh\n", exit_code=0)
    rc = main(["discoveries", path])
    assert rc == 0
    out = capsys.readouterr().out
    assert "22/tcp ssh" in out


def test_cmd_discoveries_invalid_engagement(tmp_path, capsys):
    bad = str(tmp_path / "bad.yaml")
    import pathlib
    pathlib.Path(bad).write_text("not: valid: engagement: yaml\n")
    rc = main(["discoveries", bad])
    assert rc != 0
