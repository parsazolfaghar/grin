"""Shared test setup. Force the offscreen Qt platform before any GUI test imports PyQt6 so the suite
runs headless in CI and locally without depending on each test file setting it first."""
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(autouse=True)
def _isolate_user_env(monkeypatch):
    """Keep the suite hermetic: a real ~/.grin/env on the developer's machine (loaded by cli.main via
    load_env_file) must not leak GRIN_MODEL_* into tests and flip the default backend to cloud. Make
    load_env_file a no-op for tests; cloud tests set the env explicitly with monkeypatch.setenv."""
    monkeypatch.setattr("grin.config.load_env_file", lambda *a, **k: {})
    yield
