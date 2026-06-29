"""Render an assessbench Score as a human-readable report or a JSON-serializable dict.

Precision is shown first and framed as the headline: it is the false-positive guard, the
number that says whether grin's findings can be trusted enough to send to a maintainer."""
from __future__ import annotations

from grin.assessbench.scorer import Score


def to_json(score: Score) -> dict:
    """JSON-serializable dict (tuples flattened to lists so json.dumps works)."""
    return {
        "target_id": score.target_id,
        "tp": score.tp,
        "fp": score.fp,
        "fn": score.fn,
        "precision": score.precision,
        "recall": score.recall,
        "matched": [list(pair) for pair in score.matched],
        "missed": list(score.missed),
        "spurious": list(score.spurious),
    }


def to_text(score: Score) -> str:
    lines = [
        f"assessbench — {score.target_id}",
        f"  precision {score.precision:.2f}   recall {score.recall:.2f}",
        f"  tp {score.tp}   fp {score.fp}   fn {score.fn}",
    ]
    if score.matched:
        lines.append("  matched (true positives):")
        lines += [f"    + {gid}  <-  {title}" for gid, title in score.matched]
    if score.missed:
        lines.append("  missed (false negatives):")
        lines += [f"    - {gid}" for gid in score.missed]
    if score.spurious:
        lines.append("  spurious (false positives):")
        lines += [f"    ! {title}" for title in score.spurious]
    return "\n".join(lines)
