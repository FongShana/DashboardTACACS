# tacacs_dashboard/routes/users.py
from __future__ import annotations

import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash

import re
from tacacs_dashboard.services.log_parser import get_last_login_map
from tacacs_dashboard.services.privilege import parse_privilege

from tacacs_dashboard.services.policy_store import (
    load_policy,
    save_policy,
    upsert_user,
    delete_user,
    is_reserved_olt_username,
)
from tacacs_dashboard.services.tacacs_config import _read_env
from tacacs_dashboard.services.tacacs_apply import generate_config_file, check_config_syntax
from tacacs_dashboard.services.olt_provision import provision_user_on_olt, deprovision_user_on_olt

from tacacs_dashboard.services.user_secrets_store import (
    set_user_password,
    ensure_user_has_password,
    delete_user_password,
)

bp = Blueprint("users", __name__)


# -----------------------
# Helpers: generate/check/restart + provision
# -----------------------
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
            f"Generate config ที่ {path} แล้ว แต่ syntax check FAILED. Message: {short_msg}",
            "error",
        )
        return False

    flash(
        f"Generate config สำเร็จ: {path} ({line_count} lines). Syntax check: OK. Message: {short_msg}",
        "success",
    )

    rok, rmsg = _restart_tac_plus_ng()
    rmsg_short = rmsg if len(rmsg) <= 400 else rmsg[:400] + " ... (truncated)"
    if rok:
        flash(f"Restart tac_plus-ng สำเร็จ: {rmsg_short}", "success")
        return True

    flash(f"Restart tac_plus-ng ล้มเหลว: {rmsg_short}", "error")
    return False


def _get_olt_ip_list(policy: dict) -> list[str]:
    """
    คืน list ของ IP OLT ที่จะ provision/deprovision
    - ถ้ามี policy.devices -> ใช้ทุกตัวที่มี address/ip (แนะนำ filter Online)
    - ถ้าไม่มี -> ใช้ OLT_DEFAULT_IP (ถ้ามี)
    """
    ips: list[str] = []

    for d in (policy.get("devices") or []):
        st = (d.get("status") or "").strip().lower()
        if st and st not in ("online", "up"):
            continue

        ip = (d.get("address") or d.get("ip") or "").strip()
        if ip:
            ips.append(ip)

    if not ips:
        default_ip = (_read_env("OLT_DEFAULT_IP", "") or "").strip()
        if default_ip:
            ips = [default_ip]

    uniq: list[str] = []
    for ip in ips:
        if ip not in uniq:
            uniq.append(ip)
    return uniq


def _olt_job_summary(out: str, ip: str) -> str:
    """เอาแค่บรรทัดสรุป job (กัน flash ยาว)"""
    if not out:
        return f"=== OLT TELNET JOB: {ip} ==="

    for line in str(out).splitlines():
        if "=== OLT TELNET JOB" in line:
            return line.strip()

    for line in str(out).splitlines():
        if line.strip():
            return line.strip()

    return f"=== OLT TELNET JOB: {ip} ==="


def _maybe_provision_to_olts(username: str, role: str, status: str) -> None:
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
            "เปิด OLT_AUTO_PROVISION แต่ไม่มี OLT ที่ Online ใน policy.json และไม่ได้ตั้ง OLT_DEFAULT_IP",
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
            msg = _olt_job_summary(out, ip)
            flash(
                f"Provision '{username}' -> OLT {ip} สำเร็จ (save={'ON' if save else 'OFF'}): {msg}",
                "success",
            )

        except Exception as e:
            flash(f"Provision '{username}' -> OLT {ip} ล้มเหลว: {e}", "error")


def _maybe_deprovision_from_olts(username: str) -> None:
    auto = (_read_env("OLT_AUTO_DEPROVISION", "0") or "0").strip().lower()
    if auto not in ("1", "true", "yes"):
        return

    policy = load_policy()
    olt_ips = _get_olt_ip_list(policy)
    if not olt_ips:
        flash(
            "เปิด OLT_AUTO_DEPROVISION แต่ไม่มี OLT ที่ Online ใน policy.json และไม่ได้ตั้ง OLT_DEFAULT_IP",
            "warning",
        )
        return

    auto_write = (_read_env("OLT_AUTO_WRITE", "0") or "0").strip().lower()
    save = auto_write in ("1", "true", "yes")

    for ip in olt_ips:
        try:
            out = deprovision_user_on_olt(
                ip,
                username=username,
                save=save,
                dry_run=False,
            )
            msg = _olt_job_summary(out, ip)
            flash(
                f"Deprovision '{username}' -> OLT {ip} สำเร็จ (save={'ON' if save else 'OFF'}): {msg}",
                "success",
            )

        except Exception as e:
            flash(f"Deprovision '{username}' -> OLT {ip} ล้มเหลว: {e}", "error")


# -----------------------
# Pages
# -----------------------
@bp.route("/")
def index():
    policy = load_policy()
    users = policy.get("users", [])
    roles = policy.get("roles", [])

    user_roles = [u.get("roles") or u.get("role") for u in users]
    for r in roles:
        name = r.get("name")
        r["members"] = user_roles.count(name)

    # ✅ last_login จาก authc log (login ACCEPT ล่าสุด)
    login_map = get_last_login_map(successful_only=True)

    for u in users:
        uname = (u.get("username") or u.get("name") or "").strip()
        if not uname:
            continue

        t = login_map.get(uname)
        if t:
            # ถ้าอยากให้เหมือนเดิม (ไม่โชว์ +0700) -> ตัด timezone ทิ้ง
            t2 = re.sub(r"\s[+-]\d{4}$", "", t)
            u["last_login"] = t2
        else:
            # ถ้าไม่มี log ก็เป็น "-"
            u["last_login"] = u.get("last_login") or "-"


    return render_template(
        "users.html",
        users=users,
        roles=roles,
        active_page="users",
    )


# -----------------------
# Users form actions
# -----------------------
@bp.post("/create")
def create_user_form():
    username = (request.form.get("username") or "").strip()
    role = (request.form.get("role") or "").strip()
    status = (request.form.get("status") or "Active").strip() or "Active"
    password = (request.form.get("password") or "").strip()


    if not username or not role:
        flash("กรุณากรอก Username และ Role ให้ครบ", "error")
        return redirect(url_for("users.index"))

    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,31}$", username):
        flash("Username ต้องยาว 3–32 ตัว และใช้ได้เฉพาะ A-Z a-z 0-9 _ -", "error")
        return redirect(url_for("users.index"))

    if is_reserved_olt_username(username):
        flash(f"ไม่อนุญาตให้ใช้ Username '{username}' (ถูกสงวนไว้/อาจชนกับ local user บน OLT)", "error")
        return redirect(url_for("users.index"))

    policy = load_policy()
    users = policy.get("users", [])
    roles = policy.get("roles", [])
    role_names = {r.get("name") for r in roles if r.get("name")}

    if role_names and role not in role_names:
        flash(f"Role {role} ไม่มีอยู่ในระบบ", "error")
        return redirect(url_for("users.index"))

    if any((u.get("username") or "").strip() == username for u in users):
        flash(f"User {username} มีอยู่แล้ว", "error")
        return redirect(url_for("users.index"))

    upsert_user(username=username, role=role, status=status)
    flash(f"เพิ่มผู้ใช้ {username} เรียบร้อย", "success")

    if password:
        set_user_password(username, password)
    else:
        ensure_user_has_password(username)


    ok = _run_generate_check_restart_and_flash()
    if ok:
        _maybe_provision_to_olts(username=username, role=role, status=status)

    return redirect(url_for("users.index"))


@bp.post("/delete/<username>")
def delete_user_form(username: str):
    username = (username or "").strip()
    if not username:
        flash("username ไม่ถูกต้อง", "error")
        return redirect(url_for("users.index"))

    ok = delete_user(username)
    if not ok:
        flash(f"ไม่พบผู้ใช้ {username}", "error")
        return redirect(url_for("users.index"))

    flash(f"ลบผู้ใช้ {username} เรียบร้อย", "success")

    delete_user_password(username)

    ok2 = _run_generate_check_restart_and_flash()
    if ok2:
        _maybe_deprovision_from_olts(username)

    return redirect(url_for("users.index"))


@bp.get("/edit/<username>")
def edit_user_form(username):
    policy = load_policy()
    users = policy.get("users", [])
    roles = policy.get("roles", [])

    target = None
    for u in users:
        if (u.get("username") or "").strip() == (username or "").strip():
            target = u
            break

    if not target:
        flash(f"ไม่พบผู้ใช้ {username}", "error")
        return redirect(url_for("users.index"))

    current_role = target.get("roles") or target.get("role") or ""

    return render_template(
        "user_edit.html",
        active_page="users",
        user=target,
        roles=roles,
        current_role=current_role,
    )


@bp.post("/edit/<username>")
def edit_user_submit(username):
    username = (username or "").strip()
    if not username:
        flash("username ไม่ถูกต้อง", "error")
        return redirect(url_for("users.index"))

    new_role = (request.form.get("role") or "").strip()
    new_status = (request.form.get("status") or "").strip() or "Active"
    
    new_password = (request.form.get("password") or "").strip()
    if new_password:
        set_user_password(username, new_password)


    policy = load_policy()
    roles = policy.get("roles", [])
    role_names = {r.get("name") for r in roles if r.get("name")}
    if role_names and new_role and new_role not in role_names:
        flash(f"Role {new_role} ไม่มีอยู่ในระบบ", "error")
        return redirect(url_for("users.edit_user_form", username=username))

    upsert_user(username=username, role=new_role, status=new_status)
    flash(f"อัปเดตผู้ใช้ {username} เรียบร้อยแล้ว", "success")

    ok = _run_generate_check_restart_and_flash()
    if ok:
        _maybe_provision_to_olts(username=username, role=new_role, status=new_status)

    return redirect(url_for("users.index"))


# -----------------------
# Roles: เหลือไว้แค่ Edit (ตัด Create/Delete ออก)
# -----------------------
@bp.get("/roles/<name>/edit")
def edit_role_form(name):
    policy = load_policy()
    roles = policy.get("roles", [])

    target = None
    for r in roles:
        if (r.get("name") or "").strip() == (name or "").strip():
            target = r
            break

    if not target:
        flash(f"ไม่พบ Role {name}", "error")
        return redirect(url_for("users.index"))

    return render_template(
        "role_edit.html",
        active_page="users",
        role=target,
    )


@bp.post("/roles/<name>/edit")
def edit_role_submit(name):
    name = (name or "").strip()
    policy = load_policy()
    roles = policy.get("roles", [])

    target = None
    for r in roles:
        if (r.get("name") or "").strip() == name:
            target = r
            break

    if not target:
        flash(f"ไม่พบ Role {name}", "error")
        return redirect(url_for("users.index"))

    target["description"] = (request.form.get("description") or "").strip()

    # privilege validation: must be 1..15
    priv_raw = (request.form.get("privilege") or "").strip()
    if not re.search(r"\d+", priv_raw):
        flash("Privilege ต้องเป็นตัวเลข 1-15", "error")
        return redirect(url_for("users.edit_role_form", name=name))

    priv = parse_privilege(priv_raw, default=15)
    target["privilege"] = str(priv)

    save_policy(policy)
    flash(f"อัปเดต Role {name} เรียบร้อยแล้ว", "success")
    _run_generate_check_restart_and_flash()
    return redirect(url_for("users.index"))


