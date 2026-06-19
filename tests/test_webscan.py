from grin.tools.webscan import (
    classify,
    extract_forms,
    injection_points,
    query_params,
    xss_payloads,
)


def test_payloads_carry_marker_and_real_vectors():
    pays = xss_payloads("GRINz9")
    assert len(pays) >= 4
    assert all("GRINz9" in p for p in pays)
    assert any("<svg" in p or "<script" in p for p in pays)


def test_classify_raw_means_injectable():
    payload = "<svg/onload=alert('Mk')>"
    body = f"<html>hi {payload} bye</html>"
    assert classify(body, payload, "Mk") == "raw"


def test_classify_encoded_means_escaped():
    payload = "<svg/onload=alert('Mk')>"
    body = "<p>search: &lt;svg/onload=alert('Mk')&gt; 0 results</p>"
    assert classify(body, payload, "Mk") == "encoded"


def test_classify_none_when_absent():
    assert classify("<p>nothing</p>", "<svg Mk>", "Mk") is None
    assert classify("", "<svg>", "M") is None


def test_query_params_pulls_existing_param_names():
    assert query_params("http://t/page?id=1&q=hi") == ["id", "q"]
    assert query_params("http://t/page") == []


def test_extract_forms_finds_inputs():
    html = '<form action="/login" method="POST"><input name="user"><input name="pass" type="password"></form>'
    forms = extract_forms(html)
    assert len(forms) == 1
    assert forms[0].action == "/login" and forms[0].method == "post"
    assert {i["name"] for i in forms[0].inputs} == {"user", "pass"}


def test_injection_points_union_of_url_form_and_candidates():
    # injection points = existing URL params + form input names + the candidate name list,
    # de-duplicated. This is what makes the scanner find params that are linked NOWHERE.
    html = '<form action="/s"><input name="search"></form>'
    pts = injection_points("http://t/?id=1", html)
    assert "id" in pts          # from the URL
    assert "search" in pts      # from the form
    assert "q" in pts and "file" in pts and "name" in pts   # from the candidate list
    assert len(pts) == len(set(pts))                        # de-duplicated
