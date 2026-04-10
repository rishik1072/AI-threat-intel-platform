from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor


_EXEC = ThreadPoolExecutor(max_workers=4)
_LOCK = threading.Lock()
_JOBS: dict[str, dict] = {}
_TTL_SECONDS = 10 * 60


def _gc() -> None:
    now = time.time()
    with _LOCK:
        dead = [jid for jid, j in _JOBS.items() if now - j["created_at"] > _TTL_SECONDS]
        for jid in dead:
            _JOBS.pop(jid, None)


def submit(fn, *args, **kwargs) -> str:
    _gc()
    job_id = uuid.uuid4().hex
    with _LOCK:
        _JOBS[job_id] = {
            "created_at": time.time(),
            "status": "queued",
            "result": None,
            "error": None,
            "scan_id": None,
        }

    def run():
        with _LOCK:
            _JOBS[job_id]["status"] = "running"
        try:
            res = fn(*args, **kwargs)
            with _LOCK:
                _JOBS[job_id]["status"] = "done"
                _JOBS[job_id]["result"] = res
        except Exception as e:
            with _LOCK:
                _JOBS[job_id]["status"] = "error"
                _JOBS[job_id]["error"] = str(e)

    _EXEC.submit(run)
    return job_id


def get(job_id: str) -> dict | None:
    _gc()
    with _LOCK:
        j = _JOBS.get(job_id)
        if not j:
            return None
        return {"job_id": job_id, **j}


def attach_scan_id(job_id: str, scan_id: int) -> None:
    with _LOCK:
        if job_id in _JOBS:
            _JOBS[job_id]["scan_id"] = int(scan_id)

