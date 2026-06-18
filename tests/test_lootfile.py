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
    m = re.search(r"base64 -d", cmd)
    b64 = re.search(r"printf %s '([A-Za-z0-9+/=]+)'", cmd)
    assert b64 and base64.b64decode(b64.group(1)).decode() == _key().value


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


def test_persist_never_raises():
    class Boom:
        def run(self, *a, **k):
            raise RuntimeError("runner down")
    assert persist_artifact(_key(), Boom()) is None
