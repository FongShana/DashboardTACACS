# tacacs_dashboard/services/locks.py
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import os
import time
import fcntl


def _lock_dir() -> Path:
    # Allow override via env, but default to /tmp (safe for systemd services)
    d = (os.environ.get("TACACS_DASHBOARD_LOCK_DIR") or "/tmp/tacacs_dashboard_locks").strip()
    p = Path(d)
    p.mkdir(parents=True, exist_ok=True)
    return p


@contextmanager
def file_lock(name: str, *, timeout: float = 30.0, poll_interval: float = 0.1):
    """Cross-process lock using flock().

    Works across multiple Gunicorn workers (processes). Use for any 'write' paths:
    - policy.json updates
    - user_secrets.json updates
    - generate/apply TACACS config + restart
    - OLT telnet provisioning/bootstrap (per-device lock)

    timeout: seconds to wait before raising TimeoutError
    """
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in (name or "lock"))
    lock_path = _lock_dir() / f"{safe}.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)

    start = time.time()
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if (time.time() - start) >= timeout:
                    raise TimeoutError(f"Timeout waiting for lock: {lock_path}")
                time.sleep(poll_interval)

        yield
    finally:
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        except Exception:
            # best-effort unlock
            pass


def olt_lock_name(olt_ip: str) -> str:
    ip = (olt_ip or "").strip().replace(":", "_").replace("/", "_")
    ip = ip.replace(".", "_")
    return f"olt_{ip}"


@contextmanager
def olt_lock(olt_ip: str, *, timeout: float = 60.0):
    # 1 OLT = 1 job at a time (prevents telnet sessions/CLI config-mode from colliding)
    with file_lock(olt_lock_name(olt_ip), timeout=timeout):
        yield
