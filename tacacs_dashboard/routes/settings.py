from flask import Blueprint, render_template, request, redirect, url_for, flash

from tacacs_dashboard.services.tacacs_config import build_config_text
from tacacs_dashboard.services.tacacs_apply import (
    generate_config_file,
    check_config_syntax,
)

bp = Blueprint("settings", __name__)


@bp.route("/")
def index():
    config_preview = build_config_text()
    return render_template(
        "settings.html",
        active_page="settings",
        config_preview=config_preview,
    )


@bp.post("/generate-config")
def generate_config():
    # 1) generate ไฟล์ config
    path, line_count = generate_config_file()

    # 2) เช็ค syntax ด้วย tac_plus-ng -C
    ok, message = check_config_syntax(path)

    # ตัด message ไม่ให้ยาวเกินไป (กัน flash ยาวมาก)
    short_msg = message if len(message) <= 400 else message[:400] + " ... (truncated)"

    if ok:
        flash(
            f"Generate config สำเร็จ: {path} ({line_count} lines). "
            f"Syntax check: OK. Message: {short_msg}",
            "success",
        )
    else:
        flash(
            f"Generate config ที่ {path} แล้ว แต่ syntax check FAILED. "
            f"Message: {short_msg}",
            "error",
        )

    return redirect(url_for("settings.index"))

