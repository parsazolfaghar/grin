from grin.finding import Finding
from grin.assessbench.manifest import BenchTarget, GroundTruth
from grin.assessbench.scorer import score, Score


def _gt(id, vc, loc, sev="high"):
    return GroundTruth(id=id, vuln_class=vc, location=loc, severity=sev, description="")


def _target(*gts):
    return BenchTarget(id="demo", name="Demo", image="i:1", port=3000,
                       url="http://{host}:{port}", ground_truth=tuple(gts))


def _finding(title="f", vuln_class="", location="", evidence=""):
    return Finding(title=title, target="http://127.0.0.1:3000", severity="high",
                   evidence=evidence, tool="t", command="c",
                   vuln_class=vuln_class, location=location)


def test_perfect_match_precision_recall_one():
    tgt = _target(_gt("g1", "broken-access-control", "/rest/basket/{id}"),
                  _gt("g2", "idor", "/api/users/{id}"))
    findings = [
        _finding("basket idor", "broken-access-control", "/rest/basket/5"),
        _finding("user read", "idor", "/api/users/9"),
    ]
    s = score(findings, tgt)
    assert isinstance(s, Score)
    assert s.tp == 2 and s.fp == 0 and s.fn == 0
    assert s.precision == 1.0 and s.recall == 1.0
    assert s.target_id == "demo"


def test_false_positive_lowers_precision():
    tgt = _target(_gt("g1", "broken-access-control", "/rest/basket/{id}"))
    findings = [
        _finding("real", "broken-access-control", "/rest/basket/5"),
        _finding("bogus", "sql-injection", "/login"),   # not in ground truth -> FP
    ]
    s = score(findings, tgt)
    assert s.tp == 1 and s.fp == 1 and s.fn == 0
    assert s.precision == 0.5 and s.recall == 1.0
    assert "bogus" in s.spurious[0]


def test_missed_bug_lowers_recall():
    tgt = _target(_gt("g1", "broken-access-control", "/rest/basket/{id}"),
                  _gt("g2", "ssrf", "/api/fetch"))
    findings = [_finding("real", "broken-access-control", "/rest/basket/5")]
    s = score(findings, tgt)
    assert s.tp == 1 and s.fp == 0 and s.fn == 1
    assert s.precision == 1.0 and s.recall == 0.5
    assert "g2" in s.missed


def test_same_class_wrong_location_no_match():
    tgt = _target(_gt("g1", "broken-access-control", "/rest/basket/{id}"))
    findings = [_finding("wrong place", "broken-access-control", "/totally/different")]
    s = score(findings, tgt)
    assert s.tp == 0 and s.fp == 1 and s.fn == 1   # both penalized: it's not the same bug


def test_id_wildcard_matches_any_segment():
    tgt = _target(_gt("g1", "idor", "/api/users/{id}/profile"))
    findings = [_finding("x", "idor", "http://127.0.0.1:3000/api/users/42/profile")]
    s = score(findings, tgt)
    assert s.tp == 1 and s.recall == 1.0


def test_one_finding_cannot_cover_two_ground_truths():
    # a single vague finding must not satisfy two distinct bugs (no recall inflation)
    tgt = _target(_gt("g1", "idor", "/api/users/{id}"),
                  _gt("g2", "idor", "/api/users/{id}"))   # two distinct entries, same shape
    findings = [_finding("one", "idor", "/api/users/7")]
    s = score(findings, tgt)
    assert s.tp == 1 and s.fn == 1   # only one ground-truth satisfied


def test_class_keyword_fallback_when_finding_has_no_class():
    # finding from a tool that didn't tag a class -> fall back to title keyword
    tgt = _target(_gt("g1", "broken-access-control", "/admin"))
    findings = [_finding("Broken Access Control on admin panel", "", "/admin")]
    s = score(findings, tgt)
    assert s.tp == 1 and s.precision == 1.0


def test_location_from_evidence_when_location_field_empty():
    tgt = _target(_gt("g1", "ssrf", "/api/fetch"))
    findings = [_finding("ssrf", "ssrf", "", evidence="server fetched http://x/api/fetch?u=...")]
    s = score(findings, tgt)
    assert s.tp == 1


def test_no_findings_is_precision_one_recall_zero():
    tgt = _target(_gt("g1", "idor", "/x"))
    s = score([], tgt)
    assert s.tp == 0 and s.fp == 0 and s.fn == 1
    assert s.precision == 1.0   # nothing reported -> nothing false
    assert s.recall == 0.0


# --- regression locks for the adversarial review findings ---

def test_path_prefix_does_not_falsematch():
    # CRITICAL-1: GT /admin must NOT match a finding at /admin-panel/secret
    tgt = _target(_gt("g1", "broken-access-control", "/admin"))
    findings = [_finding("x", "broken-access-control", "/admin-panel/secret")]
    s = score(findings, tgt)
    assert s.tp == 0 and s.fp == 1 and s.fn == 1


def test_deeper_path_does_not_falsematch_shallower_gt():
    # GT /api/users/{id} must NOT match a finding at /api/users/9/profile (different endpoint)
    tgt = _target(_gt("g1", "idor", "/api/users/{id}"))
    findings = [_finding("x", "idor", "/api/users/9/profile")]
    s = score(findings, tgt)
    assert s.tp == 0 and s.fp == 1


def test_hyphenated_word_does_not_trigger_class_keyword():
    # CRITICAL-2: "xss" inside "xss-like" must not satisfy the class keyword fallback
    tgt = _target(_gt("g1", "xss", "/search"))
    findings = [_finding("reflection looks xss-like here", "", "/search")]
    s = score(findings, tgt)
    assert s.tp == 0 and s.fp == 1


def test_optimal_matching_is_order_independent():
    # IMPORTANT-4: greedy would mis-score; max-matching must find tp=2 regardless of order
    tgt = _target(_gt("g1", "idor", "/u/{id}"),    # matches /u/1 and /u/2
                  _gt("g2", "idor", "/u/1"))        # matches only /u/1
    a = _finding("A", "idor", "/u/1")
    b = _finding("B", "idor", "/u/2")
    assert score([a, b], tgt).tp == 2
    assert score([b, a], tgt).tp == 2   # order must not change the count


def test_evidence_not_mined_when_location_is_set():
    # CRITICAL (final review): a finding ABOUT /api/admin must NOT be credited for /ftp just
    # because its evidence crawl log happens to mention /ftp/acquisitions.md. When location is
    # set, only location is used; evidence is the fallback only when location is empty.
    tgt = _target(_gt("g1", "broken-access-control", "/ftp/{file}"))
    findings = [_finding("admin", "broken-access-control", "/api/admin",
                         evidence="crawled: /rest/basket/1, /ftp/acquisitions.md")]
    s = score(findings, tgt)
    assert s.tp == 0 and s.fp == 1 and s.fn == 1
