"""Load + validate an assessbench ground-truth manifest — the 'answer key' for a bench target.

Pure data + validation; no Docker here (the CLI provisions via grin.dockerenv). A manifest
declares a pinned, intentionally-vulnerable real app and the known vulnerabilities the scorer
grades grin's assessment against. Fail-loud: a malformed manifest raises rather than scoring
against a silently-wrong answer key (a wrong key would corrupt every precision/recall number)."""
from __future__ import annotations
import os
import re
from dataclasses import dataclass

import yaml

# Closed vocabulary the scorer understands. Extend deliberately, in lockstep with the scorer
# and the assessment pipeline that emits these classes.
VULN_CLASSES = frozenset({
    "broken-access-control", "idor", "ssrf", "sql-injection", "command-injection",
    "xss", "auth-bypass", "path-traversal", "info-disclosure", "csrf",
    "excessive-data-exposure", "mass-assignment", "broken-authentication", "open-redirect",
})

SEVERITIES = ("info", "low", "medium", "high", "critical")

_REQUIRED = ("id", "name", "image", "port", "url", "ground_truth")
_GT_REQUIRED = ("id", "vuln_class", "location", "severity")


class ManifestError(ValueError):
    """A bench manifest is malformed or violates the schema."""


@dataclass(frozen=True)
class GroundTruth:
    id: str
    vuln_class: str
    location: str
    severity: str
    description: str = ""

    def __post_init__(self):
        # Validate here too (not only in load_manifest) so programmatic construction can't
        # smuggle a degenerate location past the scorer (e.g. "" or "{endpoint}" matched
        # everything before this guard). Location must be a concrete, whitespace-free path.
        loc = self.location
        # A concrete path ("/a/b", "/a/{id}", "/a/b (param)") OR a single-line label
        # ("JWT signing secret"). Reject only the degenerate cases the scorer can't grade: blank,
        # multi-line, or a bare "{token}" (which would match every single-segment path).
        if (not isinstance(loc, str) or not loc.strip() or "\n" in loc or "\t" in loc
                or re.fullmatch(r"\s*\{[^}]*\}\s*", loc)):
            raise ManifestError(
                f"ground_truth location must be a non-blank single-line path or label, not a bare token: {loc!r}")


@dataclass(frozen=True)
class BenchTarget:
    id: str
    name: str
    image: str
    port: int
    url: str
    ground_truth: tuple  # tuple[GroundTruth, ...]

    def resolved_url(self, host: str) -> str:
        """Fill the manifest url template with a concrete host (port comes from the manifest)."""
        return self.url.format(host=host, port=self.port)


def targets_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "targets")


def load_bench_target(target_id: str) -> BenchTarget:
    """Load a bundled ground-truth manifest by id from grin/assessbench/targets/."""
    path = os.path.join(targets_dir(), f"{target_id}.yaml")
    if not os.path.isfile(path):
        raise ManifestError(f"unknown bench target: {target_id} (no {path})")
    return load_manifest(path)


def load_manifest(path: str) -> BenchTarget:
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        raise ManifestError(f"cannot read manifest {path}: {e}") from e

    if not isinstance(data, dict):
        raise ManifestError(f"manifest {path} is not a mapping")
    for k in _REQUIRED:
        if k not in data or data[k] in (None, ""):
            raise ManifestError(f"manifest missing required field: {k}")
    if not isinstance(data["port"], int) or isinstance(data["port"], bool):
        # bool is an int subclass in Python, so `port: true` would slip through a bare
        # isinstance(int) check and resolve to port=1.
        raise ManifestError(f"port must be an integer, got {data['port']!r}")

    gt_raw = data["ground_truth"]
    if not isinstance(gt_raw, list) or not gt_raw:
        raise ManifestError("ground_truth must be a non-empty list")

    seen: set[str] = set()
    entries: list[GroundTruth] = []
    for i, g in enumerate(gt_raw):
        if not isinstance(g, dict):
            raise ManifestError(f"ground_truth[{i}] is not a mapping")
        for k in _GT_REQUIRED:
            if k not in g or g[k] in (None, ""):
                raise ManifestError(f"ground_truth[{i}] missing required field: {k}")
        vc = str(g["vuln_class"]).strip().lower()
        if vc not in VULN_CLASSES:
            raise ManifestError(f"ground_truth[{i}] unknown vuln_class: {g['vuln_class']!r}")
        sev = str(g["severity"]).strip().lower()
        if sev not in SEVERITIES:
            raise ManifestError(f"ground_truth[{i}] invalid severity: {g['severity']!r}")
        gid = str(g["id"])
        if gid in seen:
            raise ManifestError(f"duplicate ground_truth id: {gid}")
        seen.add(gid)
        entries.append(GroundTruth(
            id=gid, vuln_class=vc, location=str(g["location"]),
            severity=sev, description=str(g.get("description", "")),
        ))

    return BenchTarget(
        id=str(data["id"]), name=str(data["name"]), image=str(data["image"]),
        port=int(data["port"]), url=str(data["url"]), ground_truth=tuple(entries),
    )
