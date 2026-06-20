"""Shared test setup. Force the offscreen Qt platform before any GUI test imports PyQt6 so the suite
runs headless in CI and locally without depending on each test file setting it first."""
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(autouse=True)
def _isolate_user_env(monkeypatch, tmp_path):
    """Keep the suite hermetic on the developer's machine:
    - a real ~/.grin/env (loaded by cli.main via load_env_file) must not leak GRIN_MODEL_* into tests
      and flip the default backend to cloud -> make load_env_file a no-op (cloud tests set env explicitly);
    - tests must not pollute the real ~/.grin: redirect the app log (GRIN_APP_LOG) and the adhoc
      engagements root (GRIN_ENGAGEMENTS_ROOT) at a per-test tmp dir."""
    monkeypatch.setattr("grin.config.load_env_file", lambda *a, **k: {})
    monkeypatch.setenv("GRIN_APP_LOG", str(tmp_path / "app.log"))
    monkeypatch.setenv("GRIN_ENGAGEMENTS_ROOT", str(tmp_path / "engagements"))
    # the Grin Brain must not read/write the developer's real ~/.grin/brain during tests
    monkeypatch.setenv("GRIN_BRAIN_PATH", str(tmp_path / "brain" / "lessons.jsonl"))
    yield
