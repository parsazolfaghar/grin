from grin.tools.sqli_probe import detect_sqli_auth_bypass, main


def test_sqli_auth_bypass_detected():
    # a vulnerable login logs in (returns a token) when the email is a SQLi payload + wrong password
    def post(url, body):
        if "OR 1=1" in body.get("email", "") or "'--" in body.get("email", ""):
            return (200, '{"authentication":{"token":"TOK"}}')
        return (401, "Invalid email or password.")
    hits = detect_sqli_auth_bypass("http://t/rest/user/login", post)
    assert hits
    assert "payload" in hits[0]


def test_no_sqli_when_login_rejects_payloads():
    def post(url, body):
        return (401, "Invalid email or password.")
    assert detect_sqli_auth_bypass("http://t/rest/user/login", post) == []


def test_no_sqli_when_200_but_no_token():
    # a 200 that is NOT an authenticated session (no token) must not count as auth bypass
    def post(url, body):
        return (200, '{"status":"error"}')
    assert detect_sqli_auth_bypass("http://t/rest/user/login", post) == []


def test_main_prints_parseable_sqli_line(capsys):
    def post(url, body):
        return (200, '{"authentication":{"token":"TOK"}}') if "OR 1=1" in body.get("email", "") \
            else (401, "")
    rc = main(["--url", "http://t/"], http_post=post)
    out = capsys.readouterr().out
    assert rc == 0
    assert "SQLI" in out and "/rest/user/login" in out
