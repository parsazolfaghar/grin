"""Robust JSON object extraction from chatty model output.

Replaces the old greedy `re.search(r"\\{.*\\}")`, which spanned from the first `{` to the LAST
`}` — so a reply containing two JSON objects (e.g. a valid action followed by an echoed
done-template, with prose between) was concatenated into invalid JSON and failed to parse.

`extract_json` instead walks the text, yields each *balanced* top-level `{...}` region (ignoring
braces inside JSON string literals), and returns the FIRST candidate that parses as a dict — and,
when `want` is given, the first whose keys include one of `want`. This salvages correct-but-verbose
models and makes the live executor/analyst robust to trailing prose or example blocks.
"""
import json


def _iter_objects(raw: str):
    """Yield each balanced top-level {...} substring, respecting string literals + escapes."""
    depth = 0
    start = -1
    in_str = False
    esc = False
    for i, ch in enumerate(raw or ""):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    yield raw[start:i + 1]


def extract_json(raw, want=None):
    """First balanced JSON object that parses to a dict. If `want` is given, the first whose keys
    include any of `want`. Returns None if nothing matches."""
    for cand in _iter_objects(raw or ""):
        try:
            obj = json.loads(cand)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        if want and not any(k in obj for k in want):
            continue
        return obj
    return None
