from __future__ import annotations

from pathlib import Path
import subprocess
import os

from .locks import exclusive_lock
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


def generate_config_file(config_path: Path | str = DEFAULT_CONFIG_PATH) -> tuple[str, int]:
    """Generate devices.secret, pass.secret, and tacacs-generated.cfg (atomic).

    This function does NOT do a global mutex. For safe multi-user operation,
    call generate_check_restart() which holds a process-wide lock.
    """
    config_path = Path(config_path)

    # 1) สร้าง devices.secret + pass.secret ก่อน (เพราะ config include)
    generate_devices_secret_file()
    generate_pass_secret_file()

    # 2) สร้าง tacacs-generated.cfg (atomic)
    text = build_config_text()
    tmp_path = config_path.with_suffix(".tmp")
    tmp_path.write_text(text, encoding="utf-8")
    os.chmod(tmp_path, 0o644)
    tmp_path.replace(config_path)

    return str(config_path), len(text.splitlines())


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


def generate_devices_secret_file(dev_path: Path | str = DEVICES_SECRET_PATH) -> tuple[str, int]:
    """สร้าง devices.secret (host blocks) ก่อนสร้าง tacacs-generated.cfg

    เก็บ shared key ไว้ในไฟล์นี้ และตั้ง permission 600 เหมือน pass.secret
    """
    dev_path = Path(dev_path)
    dev_path.parent.mkdir(parents=True, exist_ok=True)

    text = build_devices_secret_text()

    tmp_path = dev_path.with_suffix(".tmp")
    tmp_path.write_text(text, encoding="utf-8")
    os.chmod(tmp_path, 0o600)
    tmp_path.replace(dev_path)

    return str(dev_path), len(text.splitlines())


def generate_pass_secret_file(pass_path: Path | str = PASS_SECRET_PATH) -> tuple[str, int]:
    pass_path = Path(pass_path)
    pass_path.parent.mkdir(parents=True, exist_ok=True)

    text = build_pass_secret_text()

    tmp_path = pass_path.with_suffix(".tmp")
    tmp_path.write_text(text, encoding="utf-8")
    os.chmod(tmp_path, 0o600)
    tmp_path.replace(pass_path)

    return str(pass_path), len(text.splitlines())


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


def generate_check_restart(config_path: Path | str = DEFAULT_CONFIG_PATH) -> dict:
    """Safe multi-user apply: generate -> syntax check -> restart (serialized).

    Returns:
      {
        "config_path": str,
        "line_count": int,
        "syntax_ok": bool,
        "syntax_message": str,
        "restart_ok": bool,
        "restart_message": str,
      }
    """
    with exclusive_lock("tacacs_apply", timeout_sec=120.0):
        cfg_path, line_count = generate_config_file(config_path)
        ok, msg = check_config_syntax(cfg_path)

        restart_ok = False
        restart_msg = "(skipped)"
        if ok:
            restart_ok, restart_msg = restart_tacacs_daemon()

        return {
            "config_path": cfg_path,
            "line_count": line_count,
            "syntax_ok": ok,
            "syntax_message": msg,
            "restart_ok": restart_ok,
            "restart_message": restart_msg,
        }
