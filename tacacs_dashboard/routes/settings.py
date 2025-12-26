# tacacs_dashboard/routes/settings.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file

from tacacs_dashboard.services.tacacs_config import build_config_text
from tacacs_dashboard.services.tacacs_apply import (
    generate_config_file,
    check_config_syntax,
)

from tacacs_dashboard.services.policy_store import (
    load_policy,
    upsert_user,
    delete_user,
)

bp = Blueprint("settings", __name__)


def _run_generate_and_flash() -> None:
    """
    สร้าง pass.secret + tacacs-generated.cfg แล้วเช็ค syntax
    (เหมือนปุ่ม Generate & Check แต่เรียกใช้ซ้ำได้จาก add/delete user)
    """
    path, line_count = generate_config_file()
    ok, message = check_config_syntax(path)
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


@bp.route("/")
def index():
    policy = load_policy()
    config_preview = build_config_text()

    # เอา roles ไปทำ dropdown
    roles = policy.get("roles", [])
    role_names = [r.get("name") for r in roles if r.get("name")]
    if not role_names:
        role_names = ["OLT_VIEW", "OLT_ENGINEER", "OLT_ADMIN"]

    return render_template(
        "settings.html",
        active_page="settings",
        config_preview=config_preview,
        policy=policy,
        role_names=role_names,
    )


@bp.post("/add-user")
def add_user():
    username = (request.form.get("username") or "").strip()
    role = (request.form.get("role") or "").strip() or "OLT_VIEW"
    status = (request.form.get("status") or "Active").strip() or "Active"

    if not username:
        flash("กรุณากรอก username", "error")
        return redirect(url_for("settings.index"))

    try:
        created = upsert_user(username=username, role=role, status=status)
    except Exception as e:
        flash(f"เพิ่ม/แก้ไข user ไม่สำเร็จ: {e}", "error")
        return redirect(url_for("settings.index"))

    flash(
        f"{'เพิ่ม' if created else 'อัปเดต'} user '{username}' role='{role}' สำเร็จ",
        "success",
    )

    # สำคัญ: ทำให้ pass.secret / tacacs-generated.cfg อัปเดตตาม policy ทันที
    _run_generate_and_flash()

    return redirect(url_for("settings.index"))


@bp.post("/delete-user/<username>")
def remove_user(username: str):
    ok = delete_user(username)
    if ok:
        flash(f"ลบ user '{username}' สำเร็จ", "success")
        _run_generate_and_flash()
    else:
        flash(f"ไม่พบ user '{username}' ใน policy.json", "error")
    return redirect(url_for("settings.index"))


@bp.post("/generate-config")
def generate_config():
    _run_generate_and_flash()
    return redirect(url_for("settings.index"))


@bp.get("/download-config")
def download_config():
    path, _line_count = generate_config_file()
    return send_file(
        path,
        mimetype="text/plain",
        as_attachment=True,
        download_name="tacacs-generated.cfg",
    )

