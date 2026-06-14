"""Run an engagement on a background thread so the UI stays responsive. The live snapshot is
read from the files the engine already persists (audit JSONL, pending store, saved result) —
no orchestrator changes. The thread runs orchestrate, then saves the result."""
import threading


class JobRunner:
    def __init__(self, eng, *, goal, orchestrate_fn, save_fn, snapshot_reader,
                 client_factory=None, executor_factory=None, runner_factory=None,
                 now_fn=None, opts=None, env=None):
        self.eng = eng
        self.goal = goal
        self._orchestrate = orchestrate_fn
        self._save = save_fn
        self._read = snapshot_reader
        self._client_factory = client_factory
        self._executor_factory = executor_factory
        self._runner_factory = runner_factory
        self._now = now_fn
        self._opts = opts or {}
        # optional tool-env override (the active deployment profile); falls back to the engagement's
        self._env = env
        self.status = "idle"
        self.error = ""
        self._thread = None

    def start(self):
        self.status = "running"
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            kw = dict(goal=self.goal, **self._opts)
            if self._client_factory:
                kw["planner_client"] = self._client_factory(self.eng)
            if self._executor_factory:
                kw["executor_client"] = self._executor_factory(self.eng)
            if self._runner_factory:
                kw["runner"] = self._runner_factory(self._env or self.eng.env)
            if self._now:
                kw["now"] = self._now()
            res = self._orchestrate(self.eng, **kw)
            if res is not None:
                self._save(self.eng, res)
                self.status = res.status if getattr(res, "status", None) else "completed"
            else:
                self.status = "completed"
        except Exception as ex:  # noqa: BLE001
            self.error = str(ex)
            self.status = "error"

    def snapshot(self):
        snap = {"status": self.status}
        if self.error:
            snap["error"] = self.error
        try:
            snap.update(self._read(self.eng))
        except Exception:  # noqa: BLE001
            pass
        return snap
