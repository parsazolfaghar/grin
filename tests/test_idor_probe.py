from grin.tools.idor_probe import probe_idor


def test_idor_detected_when_attacker_sees_victim_data():
    # attacker (user A) requests victim (user B)'s resource and gets B's data back -> IDOR
    fetch = lambda url: (200, '{"basket":[{"name":"victim-secret-item"}]}')  # noqa: E731
    hits = probe_idor(["http://t/rest/basket/2"], "victim-secret-item", fetch)
    assert len(hits) == 1
    assert hits[0]["url"].endswith("/rest/basket/2")


def test_no_idor_when_access_forbidden():
    fetch = lambda url: (403, "")  # noqa: E731
    assert probe_idor(["http://t/rest/basket/2"], "victim-secret-item", fetch) == []


def test_no_idor_when_victim_data_absent():
    # 200 but the body does NOT contain the victim's marker -> attacker only sees their own / nothing
    fetch = lambda url: (200, '{"basket":[{"name":"attacker-own-item"}]}')  # noqa: E731
    assert probe_idor(["http://t/rest/basket/2"], "victim-secret-item", fetch) == []


def test_no_idor_on_empty_marker():
    # never fire on an empty victim marker (would match everything) — guards precision
    fetch = lambda url: (200, "anything")  # noqa: E731
    assert probe_idor(["http://t/rest/basket/2"], "", fetch) == []


def test_multiple_resources_only_vulnerable_ones_reported():
    def fetch(url):
        return (200, "victim-secret-item") if url.endswith("/2") else (403, "")
    hits = probe_idor(["http://t/rest/basket/2", "http://t/rest/basket/3"],
                      "victim-secret-item", fetch)
    assert [h["url"] for h in hits] == ["http://t/rest/basket/2"]


from grin.tools.idor_probe import authenticate


def test_authenticate_extracts_token_juice_shop_shape():
    def post(url, body):
        assert url.endswith("/rest/user/login")
        assert body == {"email": "a@b.c", "password": "pw"}
        return (200, '{"authentication":{"token":"JWT-123","bid":7}}')
    assert authenticate("http://t", "a@b.c", "pw", post) == "JWT-123"


def test_authenticate_returns_none_on_bad_creds():
    def post(url, body):
        return (401, "Invalid email or password.")
    assert authenticate("http://t", "a@b.c", "wrong", post) is None


def test_authenticate_returns_none_on_unparseable_body():
    def post(url, body):
        return (200, "not json")
    assert authenticate("http://t", "a@b.c", "pw", post) is None


from grin.tools.idor_probe import main


def test_main_reports_idor(capsys):
    def post(url, body):
        return (200, '{"authentication":{"token":"T"}}')

    def fetch_factory(token):
        assert token == "T"
        return lambda url: (200, "victim-secret") if url.endswith("/2") else (403, "")
    rc = main(["--url", "http://t/", "--attacker", "a@b.c:pw",
               "--resources", "http://t/rest/basket/2,http://t/rest/basket/3",
               "--marker", "victim-secret"], http_post=post, fetch_factory=fetch_factory)
    out = capsys.readouterr().out
    assert rc == 0
    assert "IDOR" in out and "/rest/basket/2" in out
    assert "/rest/basket/3" not in out      # 403, not reachable


def test_main_auth_failure_returns_1(capsys):
    def post(url, body):
        return (401, "")
    rc = main(["--url", "http://t/", "--attacker", "a@b.c:pw",
               "--resources", "http://t/x", "--marker", "m"], http_post=post)
    assert rc == 1


from grin.tools.idor_probe import detect_crossuser_idor


def test_crossuser_idor_when_attacker_sees_identical_victim_resource():
    body = '{"id":7,"UserId":23,"Products":[]}'
    assert detect_crossuser_idor("http://t/rest/basket/7",
                                 lambda u: (200, body), lambda u: (200, body)) is True


def test_no_crossuser_idor_when_attacker_forbidden():
    assert detect_crossuser_idor("http://t/rest/basket/7",
                                 lambda u: (401, ""), lambda u: (200, '{"id":7}')) is False


def test_no_crossuser_idor_when_attacker_gets_different_resource():
    # properly secured: attacker requesting B's id gets their own / an error, not B's bytes
    assert detect_crossuser_idor("http://t/rest/basket/7",
                                 lambda u: (200, '{"id":6}'), lambda u: (200, '{"id":7}')) is False


def test_no_crossuser_idor_when_victim_body_empty():
    assert detect_crossuser_idor("http://t/x",
                                 lambda u: (200, ""), lambda u: (200, "")) is False


from grin.tools.idor_probe import login_session


def test_login_session_returns_token_and_owned_id():
    def post(url, body):
        return (200, '{"authentication":{"token":"T","bid":9}}')
    assert login_session("http://t", "a@b.c", "pw", post) == ("T", 9)


def test_main_two_user_mode_detects_idor(capsys):
    body_b = '{"id":7,"UserId":23,"Products":[]}'

    def post(url, body):
        return (200, '{"authentication":{"token":"TA","bid":6}}') if "aaa" in str(body) \
            else (200, '{"authentication":{"token":"TB","bid":7}}')

    def fetch_factory(token):
        return lambda url: (200, body_b)   # both A and B see B's resource identically -> IDOR

    rc = main(["--url", "http://t", "--user-a", "aaa@x:pw", "--user-b", "bbb@x:pw",
               "--resource", "/rest/basket/{id}"], http_post=post, fetch_factory=fetch_factory)
    out = capsys.readouterr().out
    assert rc == 0
    assert "IDOR" in out and "/rest/basket/7" in out
