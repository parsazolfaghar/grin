from grin.tools.idrive import _parse_secrets, auto_answer, detect_prompt


def test_detects_tool_prompts():
    assert detect_prompt("msf6 > ") == "msf"
    assert detect_prompt("meterpreter > ") == "meterpreter"
    assert detect_prompt("*Evil-WinRM* PS C:\\> ") == "evil_winrm"
    assert detect_prompt("root@box:/tmp# ") == "shell"


def test_password_and_sudo_never_auto_answered():
    assert detect_prompt("user@host's password: ") == "password"
    assert detect_prompt("[sudo] password for user: ") == "sudo"
    assert auto_answer("password") is None
    assert auto_answer("sudo") is None


def test_routine_confirmations_auto_answered():
    assert auto_answer("ssh_fingerprint") == "yes"
    assert auto_answer("yn_default_yes") == "Y"
    assert auto_answer("yn_default_no") == "n"
    assert auto_answer("pager") == "q"


def test_no_prompt_mid_output():
    assert detect_prompt("scanning 45%...\n") is None


def test_parse_secrets_kv():
    assert _parse_secrets(["password=hunter2", "sudo=root123"]) == {
        "password": "hunter2", "sudo": "root123"}
    assert _parse_secrets([]) == {}
    assert _parse_secrets(["bogus"]) == {}
