import base64
import re

from grin.lootfile import persist_artifact, LOOT_DIR
from grin.runner import ExecResult
from grin.secret import Secret


class _RecRunner:
    """Records the commands it's asked to run."""
    def __init__(self):
        self.commands = []

    def run(self, target, command, timeout=60):
        self.commands.append(command)
        return ExecResult(output="", exit_code=0, duration_s=0.0, timed_out=False)


def _key():
    return Secret(label="private key",
                  value="-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\nBBBB\n-----END OPENSSH PRIVATE KEY-----",
                  target="172.30.0.16", tool="curl", command="curl ...")


def test_persist_private_key_writes_real_file_on_runner():
    """A captured key must land as a real file on the runner so the NEXT objective's ssh2john/ssh
    reads it instead of guessing a path on the target (the /root/.ssh/id_rsa miss that aborted T6)."""
    r = _RecRunner()
    path = persist_artifact(_key(), r)
    assert path == f"{LOOT_DIR}/id_rsa"
    assert len(r.commands) == 1
    cmd = r.commands[0]
    assert "base64 -d" in cmd and f"> {path}" in cmd and "chmod 600" in cmd
    # the embedded base64 must decode back to the exact key bytes
    b64 = re.search(r"printf %s '([A-Za-z0-9+/=]+)'", cmd)
    assert b64 and base64.b64decode(b64.group(1)).decode() == _key().value


def test_persist_private_key_ensures_trailing_newline():
    """OpenSSH/libcrypto refuses a private key file with no trailing newline ('error in libcrypto:
    unsupported') — even though ssh2john parses it. The extractor strips the block, so the persist
    MUST re-add a trailing newline or `ssh -i` fails (the exact T6 link-4 miss)."""
    r = _RecRunner()
    persist_artifact(_key(), r)
    cmd = r.commands[0]
    assert "id_rsa" in cmd
    # a newline is appended after the decoded key bytes
    assert r"printf '\n' >>" in cmd or r'printf "\n" >>' in cmd


def test_persist_hash_appends_to_hashfile():
    r = _RecRunner()
    h = Secret(label="password hash", value="deploy:$6$abc$xyz", target="t", tool="curl", command="c")
    path = persist_artifact(h, r)
    assert path == f"{LOOT_DIR}/hashes.txt"
    assert ">>" in r.commands[0]   # appended, not overwritten (multiple hashes accumulate)


def test_persist_ignores_non_artifact_secrets():
    r = _RecRunner()
    flag = Secret(label="flag", value="GRIN{x}", target="t", tool="cat", command="c")
    assert persist_artifact(flag, r) is None
    assert r.commands == []        # nothing written for a flag


def test_decrypt_persisted_key_strips_passphrase():
    """Once the passphrase is cracked, decrypt the persisted key in place so a later objective's
    `ssh -i /tmp/loot/id_rsa` works without passing the passphrase across objectives."""
    from grin.lootfile import decrypt_persisted_key
    r = _RecRunner()
    ok = decrypt_persisted_key("sunshine", r)
    assert ok is True
    cmd = r.commands[0]
    assert "ssh-keygen -p" in cmd and "sunshine" in cmd
    assert f"-f {LOOT_DIR}/id_rsa" in cmd and "-N ''" in cmd


def test_decrypt_persisted_key_never_raises():
    from grin.lootfile import decrypt_persisted_key

    class Boom:
        def run(self, *a, **k):
            raise RuntimeError("down")
    assert decrypt_persisted_key("x", Boom()) is False


def test_persist_never_raises():
    class Boom:
        def run(self, *a, **k):
            raise RuntimeError("runner down")
    assert persist_artifact(_key(), Boom()) is None
