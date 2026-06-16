"""Orchestrates the setup actions for the wizard — no Qt, so it's fully unit-testable. The GUI pages
call these methods; all system access is injected (run/which/os_name) for tests, defaulting to the
real implementations in production."""
import shutil
import subprocess

from grin.setup import actions


def _default_run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


class SetupController:
    def __init__(self, *, run=_default_run, which=shutil.which, os_name=None,
                 env_path="~/.grin/env"):
        if os_name is None:
            from grin.platform_info import detect_platform
            os_name = detect_platform().os
        self._run = run
        self._which = which
        self.os_name = os_name
        self.env_path = env_path

    def save_key(self, api_key, *, url="https://api.deepseek.com"):
        actions.write_env(self.env_path, api_key=api_key, url=url)

    def docker_status(self):
        return actions.docker_status(self._run, self._which)

    def install_docker(self):
        plan = actions.docker_install_plan(self.os_name, self._which)
        return actions.run_install_plan(plan, self._run)

    def provision_arsenal(self):
        return actions.provision_arsenal(self._run)

    def install_grin(self, *, src, dest):
        return actions.install_grin(self.os_name, src=src, dest=dest)
