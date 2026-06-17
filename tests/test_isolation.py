"""Regression: the test suite must never write into the developer's real ~/.grin. These cover the
two leak paths we found polluting it (app.log job traces + adhoc engagement files written under the
default root). The autouse _isolate_user_env fixture (conftest) sets GRIN_APP_LOG and
GRIN_ENGAGEMENTS_ROOT at a tmp dir; these tests prove the production code honors those overrides."""
import os
from datetime import datetime

from grin.adhoc import build_adhoc_engagement
from grin.app.runner_thread import JobRunner
from grin.intent import parse_intent
from grin.orchestrator import EngagementResult


class _Eng:
    id = "iso"; env = {"kind": "local"}; audit_log = "/tmp/none.jsonl"


def test_jobrunner_log_honors_GRIN_APP_LOG():
    # GRIN_APP_LOG is redirected to tmp by the autouse fixture.
    jr = JobRunner(_Eng(), goal="g", orchestrate_fn=lambda e, **k: EngagementResult("completed", []),
                   save_fn=lambda *a: None, snapshot_reader=lambda e: {})
    jr._log("hello-isolation")
    log_path = os.environ["GRIN_APP_LOG"]
    assert "hello-isolation" in open(log_path).read()
    assert log_path != os.path.expanduser("~/.grin/app.log")  # proves we're not writing the real log


def test_adhoc_default_root_honors_GRIN_ENGAGEMENTS_ROOT():
    # No explicit root -> resolves _default_root() -> the tmp dir from GRIN_ENGAGEMENTS_ROOT.
    intent = parse_intent("bypass login page for www.test.com")
    _eng, path = build_adhoc_engagement(intent, now=datetime(2026, 6, 17, 14, 36, 0), operator="operator")
    root = os.environ["GRIN_ENGAGEMENTS_ROOT"]
    assert path.startswith(root)
    assert os.path.expanduser("~/.grin/engagements") not in path
