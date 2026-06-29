import urllib.parse

from grin.crawl import crawl_injection_points, _classify_readonly


def _site(pages):
    """pages: {path: body}. fetch resolves by URL path (with/without trailing slash)."""
    def fetch(url):
        p = urllib.parse.urlparse(url).path
        for key in (p, p.rstrip("/"), p.rstrip("/") + "/"):
            if key in pages:
                return (200, pages[key])
        return (404, "")
    return fetch


def test_classify_blocks_actions_and_off_origin():
    s = "http://t/app"
    assert _classify_readonly("http://t/app/page?id=1", s) is True
    assert _classify_readonly("http://t/logout.php", s) is False          # action segment
    assert _classify_readonly("http://t/x?do=logout", s) is False         # action query key
    assert _classify_readonly("http://t/x?next=delete", s) is False       # action-ish value
    assert _classify_readonly("http://evil/app", s) is False              # off-origin
    assert _classify_readonly("http://t/setup.php", s) is False           # setup


def test_crawl_emits_get_form_param_and_skips_logout_link():
    pages = {
        "/index.php": '<a href="/vuln/sqli/">sqli</a> <a href="/logout.php">Logout</a>',
        "/vuln/sqli/": '<form method="get"><input type="text" name="id">'
                       '<input type="submit" name="Submit" value="Submit"></form> Logout',
    }
    cands, status = crawl_injection_points("http://t/index.php", _site(pages))
    assert status == "ok"
    assert len(cands) == 1
    loc, url, field = cands[0]
    assert field == "id" and "Submit=Submit" in url and "/vuln/sqli/" in url


def test_crawl_skips_login_password_forms():
    pages = {"/index.php": '<form method="get"><input name="username">'
                           '<input type="password" name="password"></form> Logout'}
    cands, status = crawl_injection_points("http://t/index.php", _site(pages))
    assert cands == []         # a form with a password input is never an injection surface


def test_crawl_halts_on_deauth():
    # /index has a logout marker (authed); the linked page is a login form -> session lost -> HALT
    pages = {"/index.php": '<a href="/inner">inner</a> Logout',
             "/inner": '<input type="password" name="password"> please log in'}
    cands, status = crawl_injection_points("http://t/index.php", _site(pages))
    assert status == "deauth" and cands == []


def test_crawl_drops_junk_params():
    pages = {"/index.php": '<form method="get"><input name="page"><input name="csrf_token">'
                          '<input type="text" name="q"></form> Logout'}
    cands, _status = crawl_injection_points("http://t/index.php", _site(pages))
    fields = {c[2] for c in cands}
    assert fields == {"q"}     # page + csrf_token dropped, only the real param emitted
