from __future__ import annotations

from pathlib import Path
import subprocess
import os
import time

from .locks import exclusive_lock, LOCK_DIR
from .tacacs_config import (
    BASE_DIR,
    build_config_text,
    build_pass_secret_text,
    build_devices_secret_text,
    PASS_SECRET_PATH,
    DEVICES_SECRET_PATH,
)

DEFAULT_CONFIG_PATH = BASE_DIR / "tacacs-generated.cfg"
TACACS_BIN = "/usr/local/sbin/tac_plus-ng"
TACACS_SERVICE = "tac_plus-ng"

# Apply throttling / queueing (multi-user)
# - Every request to Apply touches APPLY_REQUEST_PATH.
# - The worker that owns the apply lock will do 1 apply, then (if new requests
#   arrived during the run) wait for a short quiet period and run a final apply.
# - Callers that can't get the lock quickly return {"queued": True} immediately.
APPLY_REQUEST_PATH = LOCK_DIR / "tacacs_apply.request"
APPLY_FAST_LOCK_TIMEOUT = float(os.environ.get("TACACS_APPLY_FAST_TIMEOUT", "0.2"))
APPLY_DEBOUNCE_SEC = float(os.environ.get("TACACS_APPLY_DEBOUNCE_SEC", "10"))
APPLY_DEBOUNCE_MAX_WAIT = float(os.environ.get("TACACS_APPLY_DEBOUNCE_MAX_WAIT", "30"))


def _touch_apply_request() -> None:
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    try:
        APPLY_REQUEST_PATH.touch()
    except Exception:
        # best-effort; apply still works without the marker, just without debounce
        pass


def _apply_request_mtime() -> float:
    try:
        return APPLY_REQUEST_PATH.stat().st_mtime
    except Exception:
        return 0.0


def _atomic_write_if_changed(path: Path, text: str, mode: int) -> bool:
    """Atomic write, but skip if content is identical."""
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        if path.exists():
            old = path.read_text(encoding="utf-8", errors="ignore")
            if old == text:
                return False
    except Exception:
        # If we can't read, proceed to write to keep state consistent.
        pass

    tmp_suffix = (path.suffix + ".tmp") if path.suffix else ".tmp"
    tmp_path = path.with_suffix(tmp_suffix)
    tmp_path.write_text(text, encoding="utf-8")
    os.chmod(tmp_path, mode)
    tmp_path.replace(path)
    return True


def _wait_for_quiet_requests(*, quiet_sec: float, max_wait_sec: float, poll_sec: float = 0.25) -> bool:
    """Wait until no new apply requests arrive for quiet_sec, or until max_wait_sec passes."""
    if quiet_sec <= 0:
        return True

    start = time.monotonic()
    last_change = time.monotonic()
    last_mtime = _apply_request_mtime()

    while True:
        time.sleep(max(poll_sec, 0.05))
        cur_mtime = _apply_request_mtime()
        if cur_mtime != last_mtime:
            last_mtime = cur_mtime
            last_change = time.monotonic()

        if (time.monotonic() - last_change) >= quiet_sec:
            return True
        if (time.monotonic() - start) >= max_wait_sec:
            return False


def generate_devices_secret_file(dev_path: Path | str = DEVICES_SECRET_PATH) -> tuple[str, int, bool]:
    """สร้าง devices.secret (host blocks) ก่อนสร้าง tacacs-generated.cfg

    เก็บ shared key ไว้ในไฟล์นี้ และตั้ง permission 600 เหมือน pass.secret
    """
    dev_path = Path(dev_path)
    text = build_devices_secret_text()
    changed = _atomic_write_if_changed(dev_path, text, 0o600)
    return str(dev_path), len(text.splitlines()), changed


def generate_pass_secret_file(pass_path: Path | str = PASS_SECRET_PATH) -> tuple[str, int, bool]:
    pass_path = Path(pass_path)
    text = build_pass_secret_text()
    changed = _atomic_write_if_changed(pass_path, text, 0o600)
    return str(pass_path), len(text.splitlines()), changed


def generate_config_file(config_path: Path | str = DEFAULT_CONFIG_PATH) -> tuple[str, int, bool]:
    """Generate devices.secret, pass.secret, and tacacs-generated.cfg (atomic if changed).

    This function does NOT do a global mutex. For safe multi-user operation,
    call generate_check_restart() which holds a process-wide lock.
    """
    config_path = Path(config_path)

    # 1) สร้าง devices.secret + pass.secret ก่อน (เพราะ config include)
    _dev_path, _dev_lines, dev_changed = generate_devices_secret_file()
    _pass_path, _pass_lines, pass_changed = generate_pass_secret_file()

    # 2) สร้าง tacacs-generated.cfg (atomic)
    text = build_config_text()
    cfg_changed = _atomic_write_if_changed(config_path, text, 0o644)

    changed_any = bool(dev_changed or pass_changed or cfg_changed)
    return str(config_path), len(text.splitlines()), changed_any


def check_config_syntax(config_path: Path | str = DEFAULT_CONFIG_PATH) -> tuple[bool, str]:
    """
    รัน tac_plus-ng -P เพื่อตรวจ syntax ของไฟล์ config
    คืนค่า (ok, message)
    """
    config_path = Path(config_path)

    if not config_path.exists():
        return False, f"Config file does not exist: {config_path}"

    try:
        result = subprocess.run(
            [TACACS_BIN, "-P", str(config_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        return False, f"ไม่พบคำสั่ง {TACACS_BIN} (แก้ TACACS_BIN ใน tacacs_apply.py)"
    except subprocess.TimeoutExpired:
        return False, "คำสั่ง tac_plus-ng -P timeout"

    out = (result.stdout or "").strip()
    err = (result.stderr or "").strip()
    message = out if out else err
    if not message:
        message = "(no output)"

    ok = result.returncode == 0
    return ok, message


def restart_tacacs_daemon() -> tuple[bool, str]:
    """
    restart tac_plus-ng เพื่อให้โหลด config/pass.secret ใหม่
    ต้องมี sudoers ให้ user ที่รัน web เรียก systemctl restart ได้แบบไม่ถามรหัส
    """
    try:
        r = subprocess.run(
            ["sudo", "systemctl", "restart", TACACS_SERVICE],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if r.returncode == 0:
            return True, "tac_plus-ng restarted"
        msg = (r.stderr or r.stdout or "restart failed").strip()
        return False, msg
    except Exception as e:
        return False, str(e)


def _apply_once(config_path: Path | str = DEFAULT_CONFIG_PATH) -> dict:
    cfg_path, line_count, changed = generate_config_file(config_path)
    ok, msg = check_config_syntax(cfg_path)

    restart_ok = False
    restart_msg = "(skipped)"

    if ok and changed:
        restart_ok, restart_msg = restart_tacacs_daemon()
    elif ok and not changed:
        restart_ok = True
        restart_msg = "(skipped: no changes)"

    return {
        "config_path": cfg_path,
        "line_count": line_count,
        "changed": bool(changed),
        "syntax_ok": ok,
        "syntax_message": msg,
        "restart_ok": restart_ok,
        "restart_message": restart_msg,
    }


def generate_check_restart(config_path: Path | str = DEFAULT_CONFIG_PATH) -> dict:
    """Safe multi-user apply: generate -> syntax check -> restart (serialized).

    Behavior (key for scaling to many web users):
    - Touch a request marker file.
    - Try to acquire the apply lock quickly; if busy, return {"queued": True}.
    - The lock owner performs an apply once, then if more requests arrived during
      the run, waits for a short quiet period and performs one final apply.

    Returns a dict that always includes keys similar to the old version.
    """
    _touch_apply_request()

    try:
        with exclusive_lock("tacacs_apply", timeout_sec=APPLY_FAST_LOCK_TIMEOUT, poll_sec=0.05):
            start_req = _apply_request_mtime()
            r1 = _apply_once(config_path)
            end_req = _apply_request_mtime()

            # If there were more requests during the run, debounce and re-apply once.
            if end_req > start_req:
                quiet = _wait_for_quiet_requests(
                    quiet_sec=APPLY_DEBOUNCE_SEC,
                    max_wait_sec=APPLY_DEBOUNCE_MAX_WAIT,
                )
                r2 = _apply_once(config_path)
                r2["rerun"] = True
                r2["debounce_quiet"] = bool(quiet)
                r2["first_result"] = r1
                return r2

            return r1

    except TimeoutError as e:
        return {
            "queued": True,
            "message": str(e) or "Apply is already running; request queued.",
        }
