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


def test_extract_never_raises():
    """extract() must never raise regardless of garbage input."""
    try:
        result = extract(None, None, None, None)  # type: ignore[arg-type]
        assert isinstance(result, list)
    except Exception as e:
        raise AssertionError(f"extract() raised unexpectedly: {e}")
