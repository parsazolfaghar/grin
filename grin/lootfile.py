"""Persist captured loot (private keys, password hashes) to files on the engagement runner.

Why: a key/hash is stolen into command OUTPUT during one objective, but the next objective's
executor starts with a fresh journal and doesn't hold those bytes — so it guesses a path on the
target (`/root/.ssh/id_rsa`) that doesn't exist on the runner, and the crack reads nothing (the
exact miss that aborted T6 at the crack stage). Writing the loot to a fixed file on the runner —
which the orchestrator shares across objectives — lets later objectives run ssh2john/john/ssh -i
against a real file. Pairs with the prompt telling the model these paths exist.

Never raises: persistence is best-effort, never blocks an engagement.
"""
import base64

LOOT_DIR = "/tmp/loot"

# secret.label -> (filename, append?). Keys overwrite (one current key); hashes accumulate.
_ARTIFACT_FILES = {
    "private key": ("id_rsa", False),
    "password hash": ("hashes.txt", True),
}


def persist_artifact(secret, runner, target: str = "") -> str | None:
    """Write a key/hash secret to a fixed file on the runner; return its path, or None if the secret
    isn't a persistable artifact (or on any error). Content is base64-piped so arbitrary key bytes
    survive the shell intact."""
    try:
        spec = _ARTIFACT_FILES.get(getattr(secret, "label", ""))
        if spec is None:
            return None
        fname, append = spec
        path = f"{LOOT_DIR}/{fname}"
        b64 = base64.b64encode((getattr(secret, "value", "") or "").encode()).decode()
        if append:
            cmd = (f"mkdir -p {LOOT_DIR} && printf %s '{b64}' | base64 -d >> {path} "
                   f"&& printf '\\n' >> {path}")
        else:
            # Re-add the trailing newline the extractor's .strip() removed: OpenSSH/libcrypto
            # rejects a key file with no final newline ('error in libcrypto: unsupported').
            cmd = (f"mkdir -p {LOOT_DIR} && printf %s '{b64}' | base64 -d > {path} "
                   f"&& printf '\\n' >> {path} && chmod 600 {path}")
        runner.run(target or getattr(secret, "target", ""), cmd)
        return path
    except Exception:
        return None


def decrypt_persisted_key(passphrase: str, runner, target: str = "") -> bool:
    """Strip the passphrase from the persisted key in place (ssh-keygen -p), so a later objective's
    `ssh -i /tmp/loot/id_rsa` works without carrying the passphrase across objectives. Best-effort:
    returns False on any error; a wrong passphrase just makes ssh-keygen fail harmlessly."""
    try:
        path = f"{LOOT_DIR}/id_rsa"
        pw = (passphrase or "").replace("'", "'\\''")   # safe single-quoting
        runner.run(target, f"ssh-keygen -p -P '{pw}' -N '' -f {path}")
        return True
    except Exception:
        return False
