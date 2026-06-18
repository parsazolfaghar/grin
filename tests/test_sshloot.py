from grin.tools.sshloot import candidate_users, remote_read_cmd, ssh_argv


def test_candidate_users_defaults_and_extra_and_readme():
    # README names the service account ("deploy key for the analyst service account") -> analyst
    # must be tried, and explicit --users come first, then sensible defaults.
    users = candidate_users(extra=["svc"], readme="deploy key for the analyst service account")
    assert users[0] == "svc"                 # explicit extras first
    assert "analyst" in users                # parsed from the README clue
    assert "root" in users and "deploy" in users  # defaults present
    # deduped, order-preserving
    assert len(users) == len(dict.fromkeys(users))


def test_candidate_users_parses_for_user_phrasing():
    users = candidate_users(extra=[], readme="rotate quarterly. key for ubuntu only.")
    assert "ubuntu" in users


def test_remote_read_cmd_hits_home_and_common_paths():
    c = remote_read_cmd()
    assert "~/flag.txt" in c
    assert "/root/flag.txt" in c
    # avoids a broad noisy find over all of / (which matches /sys/.../flags)
    assert "/sys" not in c


def test_ssh_argv_uses_key_and_disables_hostkey_prompt():
    argv = ssh_argv("172.30.0.17", "/tmp/loot/id_rsa", "analyst")
    assert argv[0] == "ssh"
    assert "/tmp/loot/id_rsa" in argv
    assert "analyst@172.30.0.17" in argv
    j = " ".join(argv)
    assert "StrictHostKeyChecking=no" in j and "BatchMode=yes" in j
