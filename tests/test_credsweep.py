from grin.tools.credsweep import builtin_pairs, parse_success, ssh_try_cmd


def test_builtin_pairs_bounded_and_has_common():
    pairs = builtin_pairs()
    assert ("admin", "password") in pairs or ("admin", "admin") in pairs
    assert ("root", "root") in pairs
    assert 1 <= len(pairs) <= 400          # bounded so the sweep stays fast/online-safe
    assert len(pairs) == len(set(pairs))   # deduped


def test_ssh_try_cmd_uses_sshpass_and_safe_opts():
    c = ssh_try_cmd("10.0.0.5", "admin", "p@ss", "id; cat ~/flag.txt")
    assert c.startswith("sshpass -p ")
    assert "admin@10.0.0.5" in c
    assert "StrictHostKeyChecking=no" in c
    assert "ConnectTimeout" in c          # don't hang on a closed/filtered port
    assert "id; cat ~/flag.txt" in c


def test_parse_success_detects_uid_or_flag():
    assert parse_success("uid=0(root) gid=0(root)") is True
    assert parse_success("GRIN{abc123}") is True
    assert parse_success("Permission denied (publickey,password).") is False
    assert parse_success("") is False
