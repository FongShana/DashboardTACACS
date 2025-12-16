from pathlib import Path
import subprocess

from .tacacs_config import build_config_text

CONFIG_ID = "nt-tacacs"   # ต้องตรงกับ id ในไฟล์ config

# ตำแหน่งไฟล์ config ที่จะสร้าง (dry-run)
DEFAULT_CONFIG_PATH = Path("/home/trainee25/tacacs-web/tacacs-generated.cfg")

# ถ้า tac_plus-ng อยู่ path อื่น ให้เปลี่ยนตรงนี้
TACACS_BIN = "/usr/local/sbin/tac_plus-ng"
# ตัวอย่างถ้าต้องใช้ path เต็ม:
# TACACS_BIN = "/usr/local/sbin/tac_plus-ng"


def generate_config_file(config_path: Path | str = DEFAULT_CONFIG_PATH) -> tuple[str, int]:
    """
    สร้างไฟล์ config จาก policy ปัจจุบัน
    คืนค่า (path, จำนวนบรรทัด)
    """
    config_path = Path(config_path)
    text = build_config_text()
    config_path.write_text(text, encoding="utf-8")
    line_count = len(text.splitlines())
    return str(config_path), line_count


def check_config_syntax(config_path: Path | str = DEFAULT_CONFIG_PATH) -> tuple[bool, str]:
    """
    รัน tac_plus-ng -C เพื่อตรวจ syntax ของไฟล์ config
    คืนค่า (ok, message)
    """
    config_path = Path(config_path)

    if not config_path.exists():
        return False, f"Config file does not exist: {config_path}"

    try:
        result = subprocess.run(
            [TACACS_BIN, "-P", str(config_path), CONFIG_ID],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        return False, (
            f"ไม่พบคำสั่ง {TACACS_BIN} ใน PATH. "
            "ลองเช็ค path ของ tac_plus-ng หรือแก้ TACACS_BIN ใน tacacs_apply.py"
        )
    except subprocess.TimeoutExpired:
        return False, "คำสั่ง tac_plus-ng -C ใช้เวลานานเกินไป (timeout)."

    out = (result.stdout or "").strip()
    err = (result.stderr or "").strip()
    message = out if out else err
    if not message:
        message = "(no output)"

    ok = result.returncode == 0
    return ok, message
