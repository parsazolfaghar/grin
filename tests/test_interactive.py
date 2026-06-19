from grin.interactive import auto_answer, detect_prompt


def test_detects_msf_and_meterpreter():
    assert detect_prompt("Starting metasploit...\nmsf6 > ") == "msf"
    assert detect_prompt("session 1 opened\nmeterpreter > ") == "meterpreter"


def test_detects_evil_winrm():
    assert detect_prompt("*Evil-WinRM* PS C:\\Users\\admin\\Documents> ") == "evil_winrm"


def test_password_and_sudo_are_detected_but_never_auto_answered():
    assert detect_prompt("administrator@dc01's password: ") == "password"
    assert detect_prompt("[sudo] password for user: ") == "sudo"
    # never invent a credential
    assert auto_answer("password") is None
    assert auto_answer("sudo") is None


def test_ssh_fingerprint_is_accepted():
    s = "Are you sure you want to continue connecting (yes/no/[fingerprint])? "
    assert detect_prompt(s) == "ssh_fingerprint"
    assert auto_answer("ssh_fingerprint") == "yes"


def test_yes_no_defaults_respected():
    assert detect_prompt("do you want to exploit this? [Y/n] ") == "yn_default_yes"
    assert auto_answer("yn_default_yes") == "Y"
    assert detect_prompt("perform a risky write? [y/N] ") == "yn_default_no"
    assert auto_answer("yn_default_no") == "n"


def test_pager_is_quit_so_session_never_hangs():
    assert detect_prompt("...big output...\n--More--") == "pager"
    assert auto_answer("pager") == "q"


def test_shell_prompts():
    assert detect_prompt("root@victim:/tmp# ") == "shell"
    assert detect_prompt("user@host:~$ ") == "shell"


def test_no_prompt_mid_output():
    assert detect_prompt("Scanning... 45% complete\nfound 3 hosts\n") is None
    assert detect_prompt("") is None


def test_unknown_and_command_prompts_are_not_auto_answered():
    assert auto_answer(None) is None
    assert auto_answer("shell") is None      # a command prompt — feed a real step, don't "answer" it
    assert auto_answer("meterpreter") is None
