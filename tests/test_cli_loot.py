from grin.cli import cmd_loot, build_parser
from grin.loot import LootStore, loot_dir
from grin.secret import Secret
from grin.engagement import load_engagement


def _eng(tmp_path):
    audit = str(tmp_path / "audit" / "e1.jsonl")
    p = tmp_path / "e1.yaml"
    p.write_text("id: e1\nname: n\nmode: own-lab\nscope:\n  in: [\"127.0.0.1\"]\n"
                 "roe:\n  allowed_actions: [passive]\nautonomy: autonomous\nenv: {kind: local}\n"
                 f"audit_log: {audit}\nstate: active\n")
    return str(p)


def test_loot_subcommand_parses():
    args = build_parser().parse_args(["loot", "e.yaml"])
    assert args.group == "loot"


def test_cmd_loot_prints_recorded(tmp_path, capsys):
    path = _eng(tmp_path)
    eng = load_engagement(path)
    LootStore(loot_dir(eng)).record(
        Secret("SSH password", "root:toor", "127.0.0.1", "hydra", "hydra ...", "root"),
        objective="o")
    rc = cmd_loot(path)
    assert rc == 0
    out = capsys.readouterr().out
    assert "root:toor" in out and "SSH password" in out


def test_cmd_loot_none(tmp_path, capsys):
    rc = cmd_loot(_eng(tmp_path))
    assert rc == 0
    assert "no secrets" in capsys.readouterr().out.lower()
