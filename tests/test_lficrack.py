from grin.tools.lficrack import parse_cred_hash, traversal_payloads


def test_parse_cred_hash_from_shadow_line():
    text = ("root:*:19000:0:99999:7:::\n"
            "devops:$6$abc123$DEFqsuVeryLongHashValue/with.slashes:19000:0:99999:7:::\n")
    u, h = parse_cred_hash(text)
    assert u == "devops"
    assert h == "$6$abc123$DEFqsuVeryLongHashValue/with.slashes"


def test_parse_cred_hash_ignores_locked_and_empty():
    # locked (*/!) and empty password fields are not crackable creds
    assert parse_cred_hash("root:*:19000:::\nbin:!:19000:::\n") is None
    assert parse_cred_hash("nobody::19000:::\n") is None


def test_parse_cred_hash_supports_md5_and_yescrypt():
    assert parse_cred_hash("a:$1$salt$hashval:1::\n")[1].startswith("$1$")
    assert parse_cred_hash("b:$y$j9T$salt$hashval:1::\n")[1].startswith("$y$")


def test_traversal_payloads_cover_depths_and_target():
    pays = traversal_payloads("var/backups/shadow.bak")
    assert any(p.count("../") >= 5 for p in pays)          # deep traversal present
    assert all(p.endswith("var/backups/shadow.bak") for p in pays)
    assert len(pays) == len(set(pays))                     # deduped
