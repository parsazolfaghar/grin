import os
import stat
from datetime import datetime

from grin.safety import is_self_destructive, destructive_allowed
from grin.loot import LootStore
from grin.secret import Secret
from grin.engagement import validate_engagement
from grin.runner import FakeRunner, ExecResult
from grin.spine import submit_action


def test_self_destructive_flags_host_destruction():
    for c in ["rm -rf /", "rm -rf ~", "sudo rm -rf /*", "mkfs.ext4 /dev/sda",
              "dd if=/dev/zero of=/dev/sda bs=1M", ":(){ :|:& };:", "cat x > /dev/sda"]:
        assert is_self_destructive(c), c


def test_offensive_and_benign_commands_not_flagged():
    for c in ["sqlmap -u http://t/ --dump", "nmap -sV 10.0.0.1", "hydra -l a -P rockyou.txt ssh://t",
              "msfvenom -p linux/x64/shell -o s.elf", "rm -rf /tmp/grin-work", "dd if=p of=out.bin",
              "nuclei -u http://t/"]:
        assert not is_self_destructive(c), c


def test_loot_files_are_owner_only(tmp_path):
    ls = LootStore(str(tmp_path / "e.loot"))
    ls.record(Secret("cred", "admin:pw", "t", "sqlmap", "cmd", "ctx"), objective="o")
    for fn in ("secrets.jsonl", "secrets.md"):
        mode = stat.S_IMODE(os.stat(tmp_path / "e.loot" / fn).st_mode)
        assert mode == 0o600, oct(mode)
    dmode = stat.S_IMODE(os.stat(tmp_path / "e.loot").st_mode)
    assert dmode == 0o700, oct(dmode)


def _eng(tmp_path):
    return validate_engagement({
        "id": "e", "name": "n", "mode": "own-lab",
        "scope": {"in": ["127.0.0.1"], "exclude": []},
        "roe": {"allowed_actions": ["passive", "active-scan"], "windows": []},
        "autonomy": "autonomous", "env": {"kind": "local"},
        "audit_log": str(tmp_path / "audit" / "e.jsonl"), "state": "active"})


class _BoomRunner:
    def run(self, *a, **k):
        raise AssertionError("self-destructive command should NOT have executed")


def test_spine_refuses_self_destructive_command(tmp_path, monkeypatch):
    monkeypatch.delenv("GRIN_ALLOW_DESTRUCTIVE", raising=False)
    out = submit_action(_eng(tmp_path), target="127.0.0.1", tool="bash", command="rm -rf /",
                        declared_class="active-scan", runner=_BoomRunner(), now=datetime(2026, 1, 1))
    assert out.status == "refused" and "self-guard" in out.reason


def test_destructive_override_allows_execution(tmp_path, monkeypatch):
    monkeypatch.setenv("GRIN_ALLOW_DESTRUCTIVE", "1")
    runner = FakeRunner({"rm -rf /tmp/x": ExecResult("ok", 0, 0.0, False)})
    out = submit_action(_eng(tmp_path), target="127.0.0.1", tool="bash", command="mkfs.ext4 /dev/loop0",
                        declared_class="active-scan", runner=runner, now=datetime(2026, 1, 1))
    assert out.status == "executed"   # override lets it run (operator's explicit choice)
    assert destructive_allowed() is True
