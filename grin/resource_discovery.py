"""Resource-id discovery — autonomously find a VICTIM-OWNED object detail URL (and the attacker's
own analogous one) so the hardened IDOR oracle fires end-to-end on a target with no hardcoded
resource template. Code owns the surface graph; no LLM.

Source: the target's own OpenAPI/Swagger doc (the principled "code owns the graph" surface for
API targets). From it we take collection/detail GET pairs, enumerate the collection per role, and
emit a candidate ONLY with ownership proof. The design is deliberately conservative — it biases to
SKIP on any ambiguity, because permissive discovery on a multi-tenant global list can manufacture a
false CONFIRMED that survives even the hardened oracle (an intentional shared-read catalog). The
oracle is the precision gate; this is the precision wedge that feeds it only defensible candidates.

Scope (honest): OpenAPI-described flat REST collections with an owner field. Nested ownership paths
(/users/{uid}/books/{bid}), specs that omit the collection, disjoint-scope user lists without an
owner field, and non-OpenAPI targets are follow-ups. The login-derived id path (Juice Shop's basket
id) stays as the complementary source."""
from __future__ import annotations
import json
import re
import urllib.parse
from dataclasses import dataclass

OPENAPI_PATHS = (
    "/openapi.json", "/swagger.json", "/api-docs", "/api-docs/swagger.json",
    "/v3/api-docs", "/openapi/v3", "/api/openapi.json", "/swagger/v1/swagger.json",
)
OWNER_FIELDS = ("user", "owner", "username", "userid", "user_id", "owner_id", "ownerid",
                "created_by", "createdby", "email", "author")
ARRAY_NEGATIVE_KEYS = ("errors", "messages", "links", "meta", "included", "permissions", "roles")
_PARAM_RE = re.compile(r"^\{([^}]+)\}$")


@dataclass(frozen=True)
class Pair:
    collection_path: str    # /books/v1
    detail_template: str    # /books/v1/{book_title}
    param_name: str         # book_title


def fetch_openapi(base_url, get):
    """Fetch + parse the OpenAPI/Swagger doc from common locations. get(url) -> (status, body)."""
    base = base_url.rstrip("/")
    for p in OPENAPI_PATHS:
        try:
            status, body = get(base + p)
        except Exception:
            continue
        if status != 200 or not body:
            continue
        try:
            spec = json.loads(body)
        except Exception:
            continue
        if isinstance(spec, dict) and isinstance(spec.get("paths"), dict):
            return spec
    return None


def _spec_prefix(spec):
    """The path prefix to prepend to spec paths: OAS3 servers[0].url path, or Swagger2 basePath."""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = servers[0].get("url", "")
        return urllib.parse.urlparse(url).path.rstrip("/")
    bp = spec.get("basePath")
    return (bp or "").rstrip("/")


def collection_detail_pairs(spec):
    """Flat object-by-id GET endpoints whose collection parent is ALSO a GET. Skips nested
    multi-param paths (their parent needs an instantiated id we don't resolve in this slice)."""
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return []
    prefix = _spec_prefix(spec)

    def has_get(p):
        ops = paths.get(p)
        return isinstance(ops, dict) and "get" in {k.lower() for k in ops}

    pairs = []
    for p, ops in paths.items():
        if not isinstance(ops, dict) or "get" not in {k.lower() for k in ops}:
            continue
        segs = [s for s in p.split("/") if s]
        if not segs:
            continue
        m = _PARAM_RE.match(segs[-1])
        if not m:
            continue
        if sum(1 for s in segs if _PARAM_RE.match(s)) != 1:   # exactly one param, and it's last
            continue
        parent = "/" + "/".join(segs[:-1])
        if not has_get(parent):
            continue
        pairs.append(Pair(prefix + parent, prefix + p, m.group(1)))
    return pairs


def _score_array(name, arr):
    if not isinstance(arr, list) or not arr:
        return None
    if name and str(name).lower() in ARRAY_NEGATIVE_KEYS:
        return None
    objs = [e for e in arr if isinstance(e, dict)]
    if not objs:
        return 0 if all(isinstance(e, (str, int)) for e in arr) else None   # scalar-id list
    keys = set()
    for e in objs[:5]:
        keys |= {str(k).lower() for k in e.keys()}
    return 3 if ("id" in keys or any(k in keys for k in OWNER_FIELDS)) else 1


def _find_object_array(parsed):
    """Pick the array of resource objects. Scored; a tie between two DISTINCT arrays -> None
    (ambiguous, bias to skip). Never 'first list anywhere'."""
    cands = []

    def walk(node, name=None):
        if isinstance(node, list):
            cands.append((name, node))
            for e in node:
                if isinstance(e, (dict, list)):
                    walk(e, name)
        elif isinstance(node, dict):
            for k, v in node.items():
                walk(v, k)

    walk(parsed)
    scored = sorted((s for s in ((_score_array(n, a), a) for n, a in cands) if s[0] is not None),
                    key=lambda x: x[0], reverse=True)
    if not scored:
        return None
    if len(scored) >= 2 and scored[0][0] == scored[1][0] and scored[0][1] is not scored[1][1]:
        return None
    return scored[0][1]


def _candidate_keys(param_name):
    pn = str(param_name).lower()
    keys = [param_name, pn]
    for suf in ("_id", "_title", "_name"):
        if pn.endswith(suf) and len(pn) > len(suf):
            keys.append(pn[:-len(suf)])
    if "_" in pn:
        parts = pn.split("_")
        keys.append(parts[0] + "".join(w.capitalize() for w in parts[1:]))
    keys.append("id")
    seen, out = set(), []
    for k in keys:
        if k and k not in seen:
            seen.add(k)
            out.append(k)
    return out


def _object_id(obj, param_name):
    lower = {str(k).lower(): v for k, v in obj.items()}
    for key in _candidate_keys(param_name):
        if key in obj:
            return obj[key]
        if str(key).lower() in lower:
            return lower[str(key).lower()]
    return None


def _owner_of(obj):
    lower = {str(k).lower(): v for k, v in obj.items()}
    for f in OWNER_FIELDS:
        if f in lower and isinstance(lower[f], (str, int)):
            return str(lower[f])
    return None


def _pick_owned(objs, param_name, identity):
    """An id from a row whose owner field matches the harness identity. None -> no ownership proof."""
    idl = (identity or "").strip().lower()
    if not idl or not objs:
        return None
    for o in objs:
        if not isinstance(o, dict):
            continue
        owner = _owner_of(o)
        if owner is not None and owner.strip().lower() == idl:
            rid = _object_id(o, param_name)
            if rid is not None:
                return str(rid)
    return None


def _enumerate(get, base, collection_path):
    try:
        status, body = get(base + collection_path)
    except Exception:
        return None
    if status != 200 or not body:
        return None
    try:
        return _find_object_array(json.loads(body))
    except Exception:
        return None


def _detail_url(base, detail_template, param_name, rid):
    return base + detail_template.replace("{" + param_name + "}",
                                          urllib.parse.quote(str(rid), safe=""))


def _get200(get, url):
    try:
        s, b = get(url)
    except Exception:
        return None
    return b if (s == 200 and (b or "").strip()) else None


def _candidate_for_pair(base, pair, victim, attacker, victim_identity, attacker_identity):
    vobjs = _enumerate(victim, base, pair.collection_path)
    if not vobjs:
        return None
    aobjs = _enumerate(attacker, base, pair.collection_path)
    vid = _pick_owned(vobjs, pair.param_name, victim_identity)              # ownership proof: victim
    aid = _pick_owned(aobjs or vobjs, pair.param_name, attacker_identity)   # ownership proof: attacker
    if vid is None or aid is None or str(vid) == str(aid):
        return None
    victim_url = _detail_url(base, pair.detail_template, pair.param_name, vid)
    attacker_own_url = _detail_url(base, pair.detail_template, pair.param_name, aid)
    # pre-oracle emit gate: both detail URLs 200 + distinct bytes, and the victim does NOT already
    # read the attacker's object as the same bytes (kills junk own-urls and symmetric catalogs).
    vv = _get200(victim, victim_url)
    ao = _get200(attacker, attacker_own_url)
    if vv is None or ao is None or vv == ao:
        return None
    va = _get200(victim, attacker_own_url)
    if va is not None and va == vv:
        return None
    return pair.detail_template, victim_url, attacker_own_url


def discover_idor_candidates(base_url, by_role, victim_identity, attacker_identity, *,
                             max_collections=12):
    """Returns [(location, victim_url, attacker_own_url), ...]. Read-only and conservative."""
    victim = by_role.get("victim")
    attacker = by_role.get("attacker")
    if not (victim and attacker):
        return []
    spec = fetch_openapi(base_url, by_role.get("anon") or victim) or fetch_openapi(base_url, victim)
    if not spec:
        return []
    base = base_url.rstrip("/")
    out = []
    for pair in collection_detail_pairs(spec)[:max_collections]:
        cand = _candidate_for_pair(base, pair, victim, attacker, victim_identity, attacker_identity)
        if cand:
            out.append(cand)
    return out
