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
