import pytest
from grin.assessbench.manifest import (
    load_manifest, load_bench_target, BenchTarget, GroundTruth, VULN_CLASSES, ManifestError,
)


def test_juice_shop_bench_target_loads():
    t = load_bench_target("juice-shop")
    assert isinstance(t, BenchTarget)
    assert t.id == "juice-shop"
    assert t.port == 3000
    assert len(t.ground_truth) >= 3
    # the vertical-slice classes are present and the canonical basket IDOR is in the key
    classes = {g.vuln_class for g in t.ground_truth}
    assert classes & {"idor", "broken-access-control"}
    assert any(g.location == "/rest/basket/{id}" for g in t.ground_truth)


def test_load_bench_target_unknown_raises():
    with pytest.raises(ManifestError):
        load_bench_target("does-not-exist")

VALID = """
id: demo
name: Demo App
image: example/demo:1.0
port: 3000
url: "http://{host}:{port}"
ground_truth:
  - id: bac-1
    vuln_class: broken-access-control
    location: "/rest/basket/{id}"
    severity: high
    description: "IDOR on basket"
  - id: bac-2
    vuln_class: idor
    location: "/api/users/{id}"
    severity: medium
    description: "read other user"
"""


def _write(tmp_path, text):
    p = tmp_path / "m.yaml"
    p.write_text(text)
    return str(p)


def test_load_valid(tmp_path):
    t = load_manifest(_write(tmp_path, VALID))
    assert isinstance(t, BenchTarget)
    assert t.id == "demo" and t.port == 3000
    assert len(t.ground_truth) == 2
    assert isinstance(t.ground_truth[0], GroundTruth)
    assert t.ground_truth[0].vuln_class == "broken-access-control"
    assert t.resolved_url("127.0.0.1") == "http://127.0.0.1:3000"


def test_missing_required_field(tmp_path):
    bad = VALID.replace("image: example/demo:1.0\n", "")
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, bad))


def test_unknown_vuln_class_rejected(tmp_path):
    bad = VALID.replace("vuln_class: idor", "vuln_class: made-up-class")
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, bad))


def test_invalid_severity_rejected(tmp_path):
    bad = VALID.replace("severity: medium", "severity: catastrophic")
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, bad))


def test_duplicate_ground_truth_ids_rejected(tmp_path):
    bad = VALID.replace("id: bac-2", "id: bac-1")
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, bad))


def test_empty_ground_truth_rejected(tmp_path):
    bad = 'id: x\nname: X\nimage: i:1\nport: 80\nurl: "http://{host}:{port}"\nground_truth: []\n'
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, bad))


def test_non_integer_port_rejected(tmp_path):
    bad = VALID.replace("port: 3000", 'port: "3000x"')
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, bad))


def test_bool_port_rejected(tmp_path):
    # IMPORTANT-5: bool is an int subclass; port: true must NOT pass as port=1
    bad = VALID.replace("port: 3000", "port: true")
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, bad))


def test_location_must_be_a_path(tmp_path):
    # CRITICAL-3: an all-placeholder / non-path location must be rejected
    bad = VALID.replace('location: "/rest/basket/{id}"', 'location: "{endpoint}"')
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, bad))


def test_label_location_with_spaces_allowed(tmp_path):
    # single-line labels / annotated paths (with spaces) are valid now — e.g. grin emits
    # "JWT signing secret" and "/vulnerabilities/sqli/ (id)" as finding locations.
    ok = VALID.replace('location: "/rest/basket/{id}"', 'location: "JWT signing secret"')
    load_manifest(_write(tmp_path, ok))            # must not raise


def test_blank_location_rejected(tmp_path):
    bad = VALID.replace('location: "/rest/basket/{id}"', 'location: "   "')
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, bad))


def test_vuln_classes_includes_core():
    for c in ("broken-access-control", "idor", "ssrf", "sql-injection"):
        assert c in VULN_CLASSES
