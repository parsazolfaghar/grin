from grin.tools.bac_probe import probe, main


def _fetch_map(responses):
    def fetch(url):
        for path, resp in responses.items():
            if url.endswith(path):
                return resp
        return (404, "")
    return fetch


def test_finds_sensitive_file_served_without_auth():
    fetch = _fetch_map({
        "/": (200, "SPA-SHELL"),
        "/ftp/legal.md": (200, "CONFIDENTIAL legal text"),
    })
    hits = probe("http://t", fetch, paths=["/ftp/legal.md"])
    assert len(hits) == 1
    assert hits[0]["path"] == "/ftp/legal.md"
    assert hits[0]["status"] == 200


def test_spa_shell_not_flagged():
    # Angular SPA serves the SAME shell body for unmatched routes; must not be a finding.
    fetch = _fetch_map({"/": (200, "SHELL"), "/admin": (200, "SHELL")})
    assert probe("http://t", fetch, paths=["/admin"]) == []


def test_protected_endpoint_not_flagged():
    fetch = _fetch_map({"/": (200, "SHELL"), "/api/users": (401, "")})
    assert probe("http://t", fetch, paths=["/api/users"]) == []


def test_nonsensitive_200_not_flagged():
    # a 200 with unique content but on a non-sensitive path is not a BAC finding
    fetch = _fetch_map({"/": (200, "SHELL"), "/main.js": (200, "var x=1")})
    assert probe("http://t", fetch, paths=["/main.js"]) == []


def test_empty_body_not_flagged():
    fetch = _fetch_map({"/": (200, "SHELL"), "/ftp/empty": (200, "   ")})
    assert probe("http://t", fetch, paths=["/ftp/empty"]) == []


def test_main_prints_parseable_HIT_lines(capsys):
    fetch = _fetch_map({"/": (200, "SHELL"), "/ftp/legal.md": (200, "secret")})
    rc = main(["--url", "http://t/"], fetch=fetch, paths=["/ftp/legal.md"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "HIT" in out and "/ftp/legal.md" in out and "200" in out
