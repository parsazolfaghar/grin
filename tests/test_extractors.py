from grin.extractors import extract


def test_extract_hydra_creds():
    out = "[DATA] attacking ssh://t:22/\n[22][ssh] host: 172.30.0.11   login: admin   password: password\n1 of 1 target successfully completed"
    secs = extract("hydra", "hydra -L u -P p ssh://172.30.0.11", out, "172.30.0.11")
    creds = [s for s in secs if s.label == "SSH credentials"]
    assert len(creds) == 1
    assert creds[0].value == "admin:password"
    assert creds[0].target == "172.30.0.11" and creds[0].tool == "hydra"


def test_extract_flag():
    out = "some output\nGRIN{b460fd956b584a5faefe7c92e36744f4}\nmore"
    secs = extract("sshpass", "sshpass ... cat flag", out, "172.30.0.11")
    flags = [s for s in secs if s.label == "flag"]
    assert len(flags) == 1 and flags[0].value == "GRIN{b460fd956b584a5faefe7c92e36744f4}"


def test_extract_both_and_dedup():
    out = ("[22][ssh] login: admin password: password\n"
           "[22][ssh] login: admin password: password\n"
           "GRIN{abc123}\nGRIN{abc123}\n")
    secs = extract("hydra", "cmd", out, "t")
    assert sum(1 for s in secs if s.label == "SSH credentials") == 1  # deduped
    assert sum(1 for s in secs if s.label == "flag") == 1             # deduped


def test_extract_nothing():
    assert extract("nmap", "nmap -sV t", "Starting Nmap... 22/tcp open ssh", "t") == []


def test_extract_handles_empty():
    assert extract("hydra", "x", "", "t") == []


def test_extract_hydra_multiple_creds():
    """Multiple distinct hydra lines → distinct secrets."""
    out = (
        "[22][ssh] host: 10.0.0.1   login: root   password: toor\n"
        "[22][ssh] host: 10.0.0.1   login: admin   password: admin123\n"
    )
    secs = extract("hydra", "hydra ...", out, "10.0.0.1")
    creds = [s for s in secs if s.label == "SSH credentials"]
    values = {s.value for s in creds}
    assert values == {"root:toor", "admin:admin123"}


def test_extract_multiple_flags():
    """Multiple distinct flags → distinct secrets."""
    out = "GRIN{aaaa1111}\nsome junk\nGRIN{bbbb2222}"
    secs = extract("cat", "cat /root/flag.txt", out, "t")
    flags = [s for s in secs if s.label == "flag"]
    assert len(flags) == 2


def test_extract_weird_whitespace_hydra():
    """Handles tab-separated or extra-space hydra output."""
    out = "[80][http-post-form] host: 192.168.1.1\tlogin:  user1  password:  pass1 "
    secs = extract("hydra", "cmd", out, "192.168.1.1")
    creds = [s for s in secs if s.label == "SSH credentials"]
    assert len(creds) == 1
    assert creds[0].value == "user1:pass1"


def test_extract_openssh_private_key():
    """The T6 keystone: a stolen passphrase-protected SSH key in command output must be captured as
    a secret so the orchestrator knows it has the key and plans crack->pivot instead of re-looting."""
    out = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABB0ylTslB\n"
        "YAoJAhvnDd9k1AAAAEAAAAAEAAAGXAAAAB3NzaC1y\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    secs = extract("curl", "curl ... cat /opt/deploy/id_rsa", out, "172.30.0.16")
    keys = [s for s in secs if s.label == "private key"]
    assert len(keys) == 1
    assert keys[0].value.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert keys[0].value.rstrip().endswith("-----END OPENSSH PRIVATE KEY-----")
    assert keys[0].target == "172.30.0.16"


def test_extract_rsa_private_key():
    """Classic PEM RSA key block is also captured."""
    out = ("junk before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n"
           "-----END RSA PRIVATE KEY-----\njunk after")
    secs = extract("cat", "cat id_rsa", out, "t")
    assert sum(1 for s in secs if s.label == "private key") == 1


def test_extract_john_cracked_password():
    """john prints `<password>      (<source>)` when it cracks — capture the passphrase so the
    next objective can use the key. This is what was missing when the T6 crack 'succeeded'."""
    out = ("Using default input encoding: UTF-8\n"
           "Loaded 1 password hash (SSH ...)\n"
           "hunter2          (id_rsa)\n"
           "1g 0:00:00:01 DONE\n")
    secs = extract("john", "john --wordlist=rockyou.txt key.hash", out, "172.30.0.16")
    creds = [s for s in secs if s.label == "cracked password"]
    assert len(creds) == 1
    assert creds[0].value == "hunter2"


def test_extract_john_show_colon_format():
    """SSH-key cracks come out of john as `<keyfile>:<passphrase>` (not the `pw (source)` form).
    This is the exact T6 miss: john cracked `sunshine` but it was never captured."""
    out = ("Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])\n"
           "/tmp/loot/id_rsa:sunshine\n"
           "1 password hash cracked, 0 left\n")
    secs = extract("john", "john --show /tmp/loot/key.hash", out, "172.30.0.16")
    creds = [s for s in secs if s.label == "cracked password"]
    assert len(creds) == 1
    assert creds[0].value == "sunshine"


def test_extract_unix_password_hash():
    """A shadow/backup hash line (T4 chain) is captured so it can be cracked offline."""
    out = "deploy:$6$abc123$Z9xQwErTyUiOpAsDfGhJkLzXcVbNm1234567890qwertyuiop:19000:0:99999:7:::"
    secs = extract("curl", "curl ... cat /var/backups/shadow.bak", out, "172.30.0.14")
    hashes = [s for s in secs if s.label == "password hash"]
    assert len(hashes) == 1
    assert hashes[0].value.startswith("deploy:$6$")


def test_extract_never_raises():
    """extract() must never raise regardless of garbage input."""
    try:
        result = extract(None, None, None, None)  # type: ignore[arg-type]
        assert isinstance(result, list)
    except Exception as e:
        raise AssertionError(f"extract() raised unexpectedly: {e}")
