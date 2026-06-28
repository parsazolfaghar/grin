"""Score grin's assessment findings against a bench target's ground truth.

Pure functions. The output is precision/recall plus the per-item breakdown. Matching is
deliberately conservative — a finding matches a known bug only when BOTH its vuln class and
its location line up — because the headline metric is **precision**: the guard against telling
a maintainer about a bug that isn't there. We would rather under-credit a vague finding (lower
recall) than over-credit it (inflated precision) and ship a false positive.

Known limitation (SP1): class matching is exact. A finding tagged `idor` does not match a
ground-truth `broken-access-control` even though idor is a subclass; a synonym map is deferred
to SP2 when the assessment pipeline settles which class labels it actually emits."""
from __future__ import annotations
import re
from dataclasses import dataclass

from grin.finding import Finding
from grin.assessbench.manifest import BenchTarget, GroundTruth


@dataclass(frozen=True)
class Score:
    target_id: str
    matched: tuple   # tuple[(ground_truth_id, finding_title), ...]  — true positives
    missed: tuple    # tuple[ground_truth_id, ...]                   — false negatives
    spurious: tuple  # tuple[finding_title, ...]                     — false positives
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float


def _loc_regex(gt_location: str) -> re.Pattern:
    """A ground-truth location with `{token}` placeholders becomes a regex where each
    placeholder matches exactly one path segment (`[^/]+`). Literal parts are escaped."""
    parts = re.split(r"\{[^}]*\}", gt_location.lower())
    pattern = "[^/]+".join(re.escape(p) for p in parts)
    return re.compile(pattern)


def _class_matches(finding: Finding, gt: GroundTruth) -> bool:
    if finding.vuln_class:
        return finding.vuln_class.strip().lower() == gt.vuln_class
    # Finding came from a tool that didn't tag a class — fall back to a title keyword.
    title = finding.title.lower()
    return gt.vuln_class in title or gt.vuln_class.replace("-", " ") in title


def _location_matches(finding: Finding, rx: re.Pattern) -> bool:
    haystack = f"{finding.location} {finding.evidence}".lower()
    return rx.search(haystack) is not None


def score(findings, target: BenchTarget) -> Score:
    findings = list(findings)
    used = [False] * len(findings)
    matched: list = []
    missed: list = []

    # Greedy one-to-one: each ground-truth claims the first still-unused finding that matches
    # on BOTH class and location. Deterministic given input order; a single finding can satisfy
    # at most one ground-truth entry (no recall inflation from one vague hit).
    for gt in target.ground_truth:
        rx = _loc_regex(gt.location)
        hit = None
        for i, f in enumerate(findings):
            if used[i]:
                continue
            if _class_matches(f, gt) and _location_matches(f, rx):
                hit = i
                break
        if hit is not None:
            used[hit] = True
            matched.append((gt.id, findings[hit].title))
        else:
            missed.append(gt.id)

    spurious = [findings[i].title for i in range(len(findings)) if not used[i]]
    tp, fp, fn = len(matched), len(spurious), len(missed)
    precision = tp / (tp + fp) if (tp + fp) else 1.0   # nothing reported -> nothing false
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return Score(
        target_id=target.id, matched=tuple(matched), missed=tuple(missed),
        spurious=tuple(spurious), tp=tp, fp=fp, fn=fn,
        precision=precision, recall=recall,
    )
