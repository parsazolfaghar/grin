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


def test_crawl_deauth_also_clears_post_out():
    # a POST content sink is collected on the first page, then a deauth halt fires -> post_out must
    # be emptied too (never verify ANY candidate against a dead session)
    pages = {"/index.php": '<form method="post" action="/guestbook"><textarea name="message"></textarea>'
                          '<input type="submit" name="Sign"></form><a href="/inner">i</a> Logout',
             "/inner": '<input type="password" name="password"> please log in'}
    post_out = []
    cands, status = crawl_injection_points("http://t/index.php", _site(pages),
                                           allow_destructive=True, post_out=post_out)
    assert status == "deauth" and cands == [] and post_out == []


def test_crawl_password_form_with_logout_is_not_deauth():
    # a legit authed page (e.g. brute-force) has a password input AND the logout menu -> NOT deauth
    pages = {"/index.php": '<a href="/brute/">brute</a> Logout',
             "/brute/": '<form method="get"><input name="username"><input type="password" name="password"></form>'
                        '<form method="get"><input type="text" name="ip"></form> Logout'}
    cands, status = crawl_injection_points("http://t/index.php", _site(pages))
    assert status == "ok"                       # password input alone is not deauth
    assert {c[2] for c in cands} == {"ip"}      # login form skipped, the other GET param emitted


def test_crawl_ignores_static_resources():
    # a stylesheet <link> must not be fetched/crawled (and never trip the deauth halt)
    pages = {"/index.php": '<link href="/dvwa/css/main.css"><a href="/p/">p</a> Logout',
             "/dvwa/css/main.css": "body{color:red}",          # 200, not HTML, no logout marker
             "/p/": '<form method="get"><input type="text" name="q"></form> Logout'}
    cands, status = crawl_injection_points("http://t/index.php", _site(pages))
    assert status == "ok" and {c[2] for c in cands} == {"q"}


def test_post_archetype_allowlist():
    from grin.crawl import _post_archetype_classes
    assert _post_archetype_classes("/vulnerabilities/exec/", "ip") == ["command-injection"]
    assert "path-traversal" in _post_archetype_classes("/load", "file")
    assert _post_archetype_classes("/search", "q") == ["sqli-error"]
    assert _post_archetype_classes("/account/update", "bio") == []      # not compute/lookup -> skip
    assert _post_archetype_classes("/transfer", "amount") == []          # mutating -> skip


def test_crawl_post_forms_off_by_default():
    pages = {"/index.php": '<form method="post" action="/exec"><input type="text" name="ip">'
                          '<input type="submit" name="Submit"></form> Logout'}
    post_out = []
    cands, status = crawl_injection_points("http://t/index.php", _site(pages),
                                           allow_post=False, post_out=post_out)
    assert status == "ok" and post_out == []        # POST never probed without opt-in


def test_crawl_post_forms_emits_allowlisted_when_opted_in():
    pages = {"/index.php": '<form method="post" action="/exec"><input type="text" name="ip">'
                          '<input type="hidden" name="token" value="abc"><input type="submit" name="Submit"></form> Logout'}
    post_out = []
    crawl_injection_points("http://t/index.php", _site(pages), allow_post=True, post_out=post_out)
    assert len(post_out) == 1
    pf = post_out[0]
    assert pf["field"] == "ip" and pf["classes"] == ["command-injection"]
    assert pf["action"] == "http://t/exec" and pf["form_url"] == "http://t/index.php"


def test_crawl_post_form_skips_login_and_mutating():
    pages = {"/index.php":
             '<form method="post" action="/login"><input name="user"><input type="password" name="pw"></form>'
             '<form method="post" action="/comment"><input type="text" name="body"></form> Logout'}
    post_out = []
    crawl_injection_points("http://t/index.php", _site(pages), allow_post=True, post_out=post_out)
    assert post_out == []     # login form (password) skipped; /comment not an allowlisted archetype


def test_harvest_form_inputs_picks_form_with_field():
    from grin.cookie_auth import harvest_form_inputs
    html = ('<form><input name="q"></form>'
            '<form><input name="ip" value="1.1.1.1"><input name="token" value="T"></form>')
    assert harvest_form_inputs(html, "ip") == {"ip": "1.1.1.1", "token": "T"}


def test_crawl_drops_junk_params():
    pages = {"/index.php": '<form method="get"><input name="page"><input name="csrf_token">'
                          '<input type="text" name="q"></form> Logout'}
    cands, _status = crawl_injection_points("http://t/index.php", _site(pages))
    fields = {c[2] for c in cands}
    assert fields == {"q"}     # page + csrf_token dropped, only the real param emitted


def test_post_content_classes_allowlist():
    from grin.crawl import _post_content_classes
    assert _post_content_classes("/vulnerabilities/xss_s/", "mtxMessage") == ["stored-xss"]
    assert _post_content_classes("/guestbook", "name") == ["stored-xss"]
    assert _post_content_classes("/account/update", "amount") == []     # not a content field
    assert _post_content_classes("/exec", "ip") == []                    # compute, not content


def test_crawl_content_form_needs_allow_destructive_not_allow_post():
    pages = {"/index.php": '<form method="post" action="/guestbook"><textarea name="message"></textarea>'
                          '<input type="submit" name="Sign"></form> Logout'}
    # allow_post alone must NOT emit a content sink (it is a WRITE, gated by allow_destructive)
    po = []
    crawl_injection_points("http://t/index.php", _site(pages), allow_post=True, post_out=po)
    assert po == []
    # allow_destructive emits the stored-xss candidate
    po2 = []
    crawl_injection_points("http://t/index.php", _site(pages), allow_destructive=True, post_out=po2)
    assert len(po2) == 1 and po2[0]["classes"] == ["stored-xss"] and po2[0]["field"] == "message"
