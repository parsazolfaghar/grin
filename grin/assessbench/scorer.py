"""Score grin's assessment findings against a bench target's ground truth.

Pure functions. Output is precision/recall plus the per-item breakdown. The design bias is
toward NOT over-crediting: a finding matches a known bug only when its vuln class AND an
exact endpoint path line up, because the headline metric is **precision** — the guard against
telling a maintainer about a bug that isn't real.

Matching specifics (hardened after adversarial review):
- Location match is **anchored full-match on an extracted path**, never a substring. `/admin`
  does not match `/admin-panel`; `/api/users/{id}` does not match `/api/users/9/profile`.
- Paths are extracted from a finding's `location` and `evidence` (host/scheme/query stripped),
  so a finding may offer several candidate paths; any one exact-matching the ground-truth
  pattern counts.
- Class keyword fallback (for findings with no `vuln_class`) requires a whole-token match, so
  `xss` does not match `xss-like`.
- Finding↔ground-truth assignment is an **optimal maximum bipartite matching**, so the
  tp/fp/fn counts are reproducible regardless of the order findings were emitted.

Known limitation (SP1): class matching is exact — a finding tagged `idor` does not match a
ground-truth `broken-access-control`. A synonym map is deferred to SP2."""
from __future__ import annotations
import re
from dataclasses import dataclass

from grin.finding import Finding
from grin.assessbench.manifest import BenchTarget, GroundTruth

_SCHEME_HOST = re.compile(r"https?://[^/\s]+", re.I)
_PATH_TOKEN = re.compile(r"/[^\s?#\"'<>)]*")


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


def _loc_pattern(gt_location: str) -> re.Pattern:
    """Anchored regex for a ground-truth location; each `{token}` matches one path segment."""
    parts = re.split(r"\{[^}]*\}", gt_location.lower())
    body = "[^/]+".join(re.escape(p) for p in parts)
    return re.compile("^" + body + "$")


def _candidate_paths(text: str) -> list[str]:
    """Extract candidate endpoint paths from free text (a location field or evidence prose).

    Scheme+host is stripped first so a URL's path becomes a bare path; query/fragment are
    dropped at the token boundary. Trailing slash normalized (root stays '/')."""
    if not text:
        return []
    stripped = _SCHEME_HOST.sub(" ", text)
    out = []
    for tok in _PATH_TOKEN.findall(stripped):
        norm = tok.rstrip("/").lower() or "/"
        out.append(norm)
    return out


def _class_matches(finding: Finding, gt: GroundTruth) -> bool:
    if finding.vuln_class:
        return finding.vuln_class.strip().lower() == gt.vuln_class
    # Finding from a tool that didn't tag a class — fall back to a whole-token title keyword.
    # `(?<![\w-])...(?![\w-])` so neither word chars nor hyphens may abut (kills 'xss-like').
    title = finding.title.lower()
    for kw in {gt.vuln_class, gt.vuln_class.replace("-", " ")}:
        if re.search(r"(?<![\w-])" + re.escape(kw) + r"(?![\w-])", title):
            return True
    return False


def _location_matches(finding: Finding, pat: re.Pattern) -> bool:
    # Use the explicit location field when set; fall back to mining paths out of evidence ONLY
    # when location is empty (a tool that didn't tag a location). Otherwise a verbose evidence
    # crawl log that incidentally mentions the ground-truth path would wrongly credit a finding
    # that is actually about a different endpoint — a false true-positive (inflated precision).
    candidates = _candidate_paths(finding.location) or _candidate_paths(finding.evidence)
    for cand in candidates:
        if pat.fullmatch(cand):
            return True
    return False


def _max_matching(adjacency: list[list[int]], n_findings: int) -> list[int]:
    """Optimal maximum bipartite matching (Kuhn's augmenting paths). Deterministic given the
    order of `adjacency`. Returns gt_index -> finding_index (or -1 if unmatched)."""
    finding_to_gt = [-1] * n_findings
    gt_to_finding = [-1] * len(adjacency)

    def augment(g: int, seen: list[bool]) -> bool:
        for f in adjacency[g]:
            if not seen[f]:
                seen[f] = True
                if finding_to_gt[f] == -1 or augment(finding_to_gt[f], seen):
                    finding_to_gt[f] = g
                    gt_to_finding[g] = f
                    return True
        return False

    for g in range(len(adjacency)):
        augment(g, [False] * n_findings)
    return gt_to_finding


def score(findings, target: BenchTarget) -> Score:
    findings = list(findings)
    # Build the match graph: which findings legitimately match each ground-truth entry.
    adjacency: list[list[int]] = []
    for gt in target.ground_truth:
        pat = _loc_pattern(gt.location)
        adjacency.append([i for i, f in enumerate(findings)
                          if _class_matches(f, gt) and _location_matches(f, pat)])

    gt_to_finding = _max_matching(adjacency, len(findings))

    matched, missed = [], []
    for g, gt in enumerate(target.ground_truth):
        f = gt_to_finding[g]
        if f != -1:
            matched.append((gt.id, findings[f].title))
        else:
            missed.append(gt.id)
    # A finding is a FALSE POSITIVE only if it matches NO ground-truth entry at all. A finding
    # that matches a real bug is never an FP — even if the max-matching assigned that bug to a
    # different finding (e.g. several confidential files under one exposed /ftp dir all match the
    # same ground-truth entry). Recall stays GT-centric (the max-matching above), so a single
    # vague finding still cannot inflate it.
    matches_some_gt = {i for adj in adjacency for i in adj}
    spurious = [findings[i].title for i in range(len(findings)) if i not in matches_some_gt]

    tp, fp, fn = len(matched), len(spurious), len(missed)
    n_findings = len(findings)
    precision = (n_findings - fp) / n_findings if n_findings else 1.0   # findings that hit a real bug
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return Score(
        target_id=target.id, matched=tuple(matched), missed=tuple(missed),
        spurious=tuple(spurious), tp=tp, fp=fp, fn=fn,
        precision=precision, recall=recall,
    )
