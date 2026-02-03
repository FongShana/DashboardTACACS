# tacacs_dashboard/services/locks.py
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import os
import time
import fcntl

# Lock files live next to policy.json/secret.env for easy ops/debug.
BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOCK_DIR = BASE_DIR / ".locks"


@contextmanager
def exclusive_lock(name: str, *, timeout_sec: float = 30.0, poll_sec: float = 0.1):
    """Inter-process mutex using fcntl.flock.

    - Safe across multiple Gunicorn workers/processes.
    - Auto-released when the process exits.
    - Uses a lock file under BASE_DIR/.locks/<name>.lock

    Args:
      name: logical lock name (e.g., 'policy', 'tacacs_apply')
      timeout_sec: maximum wait time before raising TimeoutError
      poll_sec: sleep between retries when lock is held
    """

    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = LOCK_DIR / f"{(name or 'lock').strip()}.lock"

    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    start = time.monotonic()

    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if (time.monotonic() - start) >= timeout_sec:
                raise TimeoutError(f"Timeout acquiring lock: {lock_path}")
            time.sleep(poll_sec)

    # Best-effort: write some debug metadata (no secrets)
    try:
        os.ftruncate(fd, 0)
        meta = f"pid={os.getpid()} acquired_at={time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        os.write(fd, meta.encode("utf-8", errors="ignore"))
        os.fsync(fd)
    except Exception:
        pass

    try:
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
