"""Shared test setup. Force the offscreen Qt platform before any GUI test imports PyQt6 so the suite
runs headless in CI and locally without depending on each test file setting it first."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
