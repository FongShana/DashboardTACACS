# tacacs_dashboard/routes/settings.py
from __future__ import annotations

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file

from tacacs_dashboard.services.tacacs_config import build_config_text, _read_env
from tacacs_dashboard.services.tacacs_apply import generate_config_file, check_config_syntax
from tacacs_dashboard.services.policy_store import load_policy, upsert_user, delete_user

# ✅ Auto provision to OLT
from tacacs_dashboard.services.olt_provision import provision_user_on_olt

import subprocess

bp = Blueprint("settings", __name__)


def _restart_tac_plus_ng() -> tuple[bool, str]:
    try:
        r = subprocess.run(
            ["/usr/bin/sudo", "/bin/systemctl", "restart", "tac_plus-ng"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        ok = (r.returncode == 0)
        msg = (r.stdout or r.stderr or "").strip() or "(no output)"
        return ok, msg
    except Exception as e:
        return False, str(e)


def _run_generate_check_restart_and_flash() -> bool:
    """
    1) generate pass.secret + tacacs-generated.cfg
    2) syntax check (-P)
    3) restart tac_plus-ng (ถ้า syntax OK)
    return True ถ้าทุกอย่าง OK
    """
    path, line_count = generate_config_file()
    ok, message = check_config_syntax(path)
    short_msg = message if len(message) <= 400 else message[:400] + " ... (truncated)"

    if not ok:
        flash(
            f"Generate config ที่ {path} แล้ว แต่ syntax check FAILED. "
            f"Message: {short_msg}",
            "error",
        )
        return False

    flash(
        f"Generate config สำเร็จ: {path} ({line_count} lines). "
        f"Syntax check: OK. Message: {short_msg}",
        "success",
    )

    # restart tac_plus-ng ให้ใช้ config ใหม่ทันที
    rok, rmsg = _restart_tac_plus_ng()
    rmsg_short = rmsg if len(rmsg) <= 400 else rmsg[:400] + " ... (truncated)"
    if rok:
        flash(f"Restart tac_plus-ng สำเร็จ: {rmsg_short}", "success")
        return True
    else:
        flash(f"Restart tac_plus-ng ล้มเหลว: {rmsg_short}", "error")
        return False


def _get_olt_ip_list(policy: dict) -> list[str]:
    """
    คืน list ของ IP OLT ที่จะ provision
    - ถ้ามี policy.devices -> ใช้ทุกตัวที่มี address/ip
    - ถ้าไม่มี -> ใช้ OLT_DEFAULT_IP (ถ้ามี)
    """
    ips: list[str] = []

    for d in (policy.get("devices") or []):
        ip = (d.get("address") or d.get("ip") or "").strip()
        if ip:
            ips.append(ip)

    if not ips:
        default_ip = (_read_env("OLT_DEFAULT_IP", "") or "").strip()
        if default_ip:
            ips = [default_ip]

    # กันซ้ำ
    uniq: list[str] = []
    for ip in ips:
        if ip not in uniq:
            uniq.append(ip)
    return uniq


def _maybe_provision_to_olts(username: str, role: str, status: str) -> None:
    """
    ถ้าเปิด OLT_AUTO_PROVISION=1:
      - telnet ไปสร้าง/ผูก user-name บน OLT ตาม role
      - save ขึ้นกับ OLT_AUTO_WRITE (0/1)
    """
    # provision เฉพาะ Active
    if (status or "").strip().lower() not in ("active", "enable", "enabled"):
        return

    auto = (_read_env("OLT_AUTO_PROVISION", "0") or "0").strip().lower()
    if auto not in ("1", "true", "yes"):
        return

    policy = load_policy()
    olt_ips = _get_olt_ip_list(policy)
    if not olt_ips:
        flash(
            "เปิด OLT_AUTO_PROVISION แต่ยังไม่ตั้ง OLT_DEFAULT_IP และไม่มี devices ใน policy.json",
            "warning",
        )
        return

    auto_write = (_read_env("OLT_AUTO_WRITE", "0") or "0").strip().lower()
    save = auto_write in ("1", "true", "yes")

    for ip in olt_ips:
        try:
            out = provision_user_on_olt(
                ip,
                username=username,
                role=role,
                save=save,
                dry_run=False,
            )
            msg = out if len(out) <= 400 else out[:400] + " ... (truncated)"
            flash(
                f"Provision '{username}' -> OLT {ip} สำเร็จ (save={'ON' if save else 'OFF'}): {msg}",
                "success",
            )
        except Exception as e:
            flash(f"Provision '{username}' -> OLT {ip} ล้มเหลว: {e}", "error")


@bp.route("/")
def index():
    policy = load_policy()
    config_preview = build_config_text()

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

    # 1) generate + check + restart tac_plus-ng
    ok = _run_generate_check_restart_and_flash()

    # 2) provision ไป OLT (ถ้าเปิด auto)
    if ok:
        _maybe_provision_to_olts(username=username, role=role, status=status)

    return redirect(url_for("settings.index"))


@bp.post("/delete-user/<username>")
def remove_user(username: str):
    ok = delete_user(username)
    if ok:
        flash(f"ลบ user '{username}' สำเร็จ", "success")
        _run_generate_check_restart_and_flash()
        # NOTE: ยังไม่ทำลบจาก OLT ตามที่คุณบอก
    else:
        flash(f"ไม่พบ user '{username}' ใน policy.json", "error")
    return redirect(url_for("settings.index"))


@bp.post("/generate-config")
def generate_config():
    _run_generate_check_restart_and_flash()
    return redirect(url_for("settings.index"))


