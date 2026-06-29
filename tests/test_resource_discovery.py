from grin.resource_discovery import (
    collection_detail_pairs, _find_object_array, _object_id, _owner_of, _pick_owned,
    fetch_openapi, discover_idor_candidates, Pair,
)


# --- OpenAPI -> collection/detail pairs ---

def _spec(paths, **extra):
    s = {"paths": paths}
    s.update(extra)
    return s


def test_pairs_extracts_flat_collection_detail():
    spec = _spec({
        "/books/v1": {"get": {}, "post": {}},
        "/books/v1/{book_title}": {"get": {}},
        "/users/v1": {"get": {}},
        "/users/v1/{username}": {"get": {}},
    })
    pairs = collection_detail_pairs(spec)
    assert Pair("/books/v1", "/books/v1/{book_title}", "book_title") in pairs
    assert Pair("/users/v1", "/users/v1/{username}", "username") in pairs


def test_pairs_skips_detail_without_get_collection_parent():
    spec = _spec({"/books": {"post": {}}, "/books/{id}": {"get": {}}})   # parent is POST-only
    assert collection_detail_pairs(spec) == []


def test_pairs_skips_nested_multi_param():
    spec = _spec({
        "/users/{uid}/books": {"get": {}},
        "/users/{uid}/books/{bid}": {"get": {}},
    })
    assert collection_detail_pairs(spec) == []   # parent needs an instantiated {uid} — out of scope


def test_pairs_applies_basepath_prefix():
    spec = _spec({"/books": {"get": {}}, "/books/{id}": {"get": {}}}, basePath="/api")
    pairs = collection_detail_pairs(spec)
    assert pairs[0].collection_path == "/api/books" and pairs[0].detail_template == "/api/books/{id}"


def test_pairs_applies_oas3_servers_prefix():
    spec = _spec({"/books": {"get": {}}, "/books/{id}": {"get": {}}},
                 servers=[{"url": "http://h/api/v2"}])
    assert collection_detail_pairs(spec)[0].collection_path == "/api/v2/books"


# --- locating the object array ---

def test_find_object_array_picks_named_collection():
    body = {"Books": [{"book_title": "a", "user": "x"}], "total": 1}
    assert _find_object_array(body) == [{"book_title": "a", "user": "x"}]


def test_find_object_array_skips_negative_keys():
    body = {"errors": [{"id": 1}], "data": [{"id": 9, "owner": "x"}]}
    assert _find_object_array(body) == [{"id": 9, "owner": "x"}]


def test_find_object_array_ambiguous_tie_returns_none():
    # two distinct, equally-scored object arrays -> ambiguous -> skip
    body = {"a": [{"id": 1}], "b": [{"id": 2}]}
    assert _find_object_array(body) is None


# --- field mapping + ownership ---

def test_object_id_maps_param_to_field():
    assert _object_id({"book_title": "t", "user": "x"}, "book_title") == "t"
    assert _object_id({"bookId": 5}, "book_id") == 5          # camelCase variant
    assert _object_id({"id": 7}, "whatever") == 7             # falls back to id


def test_owner_and_pick_owned():
    objs = [{"book_title": "a", "user": "alice"}, {"book_title": "b", "user": "bob"}]
    assert _owner_of(objs[0]) == "alice"
    assert _pick_owned(objs, "book_title", "BOB") == "b"      # case-folded owner match
    assert _pick_owned(objs, "book_title", "carol") is None   # no ownership proof -> None


# --- end-to-end discovery against a synthetic VAmPI-like app ---

def _vampi_like(*, owner_field=True, shared_catalog=False):
    """Build by_role callables. Books owned by 'vic' and 'atk'; each book has a distinct secret.
    owner_field=False removes the owner attribution (multi-tenant, unprovable -> must SKIP).
    shared_catalog=True makes the rows owner-less reference data (must SKIP)."""
    books = {"vbook": {"book_title": "vbook", "secret": "VS", "user": "vic"},
             "abook": {"book_title": "abook", "secret": "AS", "user": "atk"}}
    spec = {"paths": {"/books/v1": {"get": {}}, "/books/v1/{book_title}": {"get": {}}}}

    def make(_role):
        def get(url, method="GET", json=None):
            if url.endswith("/openapi.json"):
                return (200, _J.dumps(spec))
            if url.endswith("/books/v1"):
                rows = [dict(b) for b in books.values()]
                if not owner_field or shared_catalog:
                    rows = [{"book_title": b["book_title"], "secret": b["secret"]} for b in books.values()]
                return (200, _J.dumps({"Books": rows}))
            for t, b in books.items():
                if url.endswith("/books/v1/" + t):
                    return (200, _J.dumps(b))     # any authed role reads any book = BOLA
            return (404, "")
        return get
    return {"anon": lambda u, method="GET", json=None: (404, ""),
            "victim": make("v"), "attacker": make("a")}


import json as _J


def test_discover_emits_owner_proven_idor_candidate():
    cands = discover_idor_candidates("http://t", _vampi_like(), "vic", "atk")
    assert len(cands) == 1
    location, victim_url, attacker_own_url = cands[0]
    assert location == "/books/v1/{book_title}"
    assert victim_url.endswith("/books/v1/vbook")           # victim's owned book
    assert attacker_own_url.endswith("/books/v1/abook")     # attacker's own (negative control)


def test_discover_skips_when_no_owner_field():
    # rows have no owner attribution -> cannot prove ownership -> SKIP (the catalog FP guard)
    assert discover_idor_candidates("http://t", _vampi_like(owner_field=False), "vic", "atk") == []


def test_discover_skips_without_openapi():
    by_role = {"anon": lambda u, method="GET", json=None: (404, ""),
               "victim": lambda u, method="GET", json=None: (404, ""),
               "attacker": lambda u, method="GET", json=None: (404, "")}
    assert discover_idor_candidates("http://t", by_role, "vic", "atk") == []


def test_discover_sqli_candidates_from_detail_params():
    from grin.resource_discovery import discover_sqli_candidates
    spec = {"paths": {"/users/v1": {"get": {}}, "/users/v1/{username}": {"get": {}}}}
    by_role = {"anon": lambda u, method="GET", json=None:
               (200, _J.dumps(spec)) if u.endswith("/openapi.json") else (404, "")}
    cands = discover_sqli_candidates("http://t", by_role)
    assert cands == [("/users/v1/{username}", "http://t/users/v1/{inject}")]


def test_is_safe_get_path_excludes_side_effecting_gets():
    from grin.resource_discovery import _is_safe_get_path
    assert _is_safe_get_path("/users/v1/_debug") is True
    assert _is_safe_get_path("/books/v1") is True
    assert _is_safe_get_path("/createdb") is False        # create prefix + db suffix
    assert _is_safe_get_path("/users/v1/{username}") is False   # path param
    assert _is_safe_get_path("/jobs/run") is False        # action segment
    assert _is_safe_get_path("/openapi.json") is False    # the spec itself


def test_discover_exposure_candidates_skips_createdb():
    from grin.resource_discovery import discover_exposure_candidates
    spec = {"paths": {"/createdb": {"get": {}}, "/users/v1/_debug": {"get": {}},
                      "/users/v1/{username}": {"get": {}}}}
    by_role = {"anon": lambda u, method="GET", json=None:
               (200, _J.dumps(spec)) if u.endswith("/openapi.json") else (404, "")}
    cands = discover_exposure_candidates("http://t", by_role)
    locs = [c[0] for c in cands]
    assert "/users/v1/_debug" in locs and "/createdb" not in locs


def test_discover_mass_assignment_target_finds_register_and_profile():
    from grin.resource_discovery import discover_mass_assignment_target
    spec = {"paths": {"/users/v1/register": {"post": {}}, "/me": {"get": {}},
                      "/members": {"get": {}}}}     # /members must NOT be mistaken for /me
    by_role = {"anon": lambda u, method="GET", json=None:
               (200, _J.dumps(spec)) if u.endswith("/openapi.json") else (404, "")}
    ma = discover_mass_assignment_target("http://t", by_role)
    assert ma["register_url"] == "http://t/users/v1/register" and ma["profile_url"] == "http://t/me"


def test_discover_mass_assignment_target_none_without_register():
    from grin.resource_discovery import discover_mass_assignment_target
    spec = {"paths": {"/api/Users": {"post": {}}, "/me": {"get": {}}}}   # no register-named path
    by_role = {"anon": lambda u, method="GET", json=None:
               (200, _J.dumps(spec)) if u.endswith("/openapi.json") else (404, "")}
    assert discover_mass_assignment_target("http://t", by_role) is None


def test_fetch_openapi_tries_common_locations():
    def get(url):
        return (200, _J.dumps({"paths": {"/x": {"get": {}}}})) if url.endswith("/swagger.json") else (404, "")
    assert fetch_openapi("http://t", get)["paths"] == {"/x": {"get": {}}}
