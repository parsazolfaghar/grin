from grin.web import extract_forms, reflection, xss_payloads


def test_payloads_all_carry_the_marker():
    pays = xss_payloads("GRINXSS123")
    assert len(pays) >= 4
    assert all("GRINXSS123" in p for p in pays)
    assert any("<svg" in p or "<script" in p for p in pays)  # real HTML/script vectors present


def test_reflection_raw_means_injectable():
    payload = "<svg/onload=alert('M1')>"
    body = f"<html><body>hi {payload} bye</body></html>"
    assert reflection(body, payload, "M1") == "raw"


def test_reflection_encoded_means_app_escaped_it():
    payload = "<svg/onload=alert('M2')>"
    body = "<html>search: &lt;svg/onload=alert('M2')&gt; (0 results)</html>"
    assert reflection(body, payload, "M2") == "encoded"


def test_reflection_none_when_absent():
    assert reflection("<html>nothing here</html>", "<svg M3>", "M3") is None
    assert reflection("", "<svg>", "M") is None


def test_extract_forms_finds_action_method_and_inputs():
    html = """
      <form action="/login" method="POST">
        <input name="user" type="text">
        <input name="pass" type="password">
        <textarea name="comment"></textarea>
        <input type="submit" value="Go">
      </form>
      <form action="/search"><input name="q"></form>
    """
    forms = extract_forms(html)
    assert len(forms) == 2
    login = forms[0]
    assert login.action == "/login" and login.method == "post"
    names = {i["name"] for i in login.inputs}
    assert {"user", "pass", "comment"} <= names
    assert forms[1].action == "/search" and forms[1].method == "get"


def test_extract_forms_empty_html():
    assert extract_forms("") == []
    assert extract_forms("<p>no forms</p>") == []
