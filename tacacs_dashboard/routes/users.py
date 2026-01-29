# tacacs_dashboard/routes/users.py
from __future__ import annotations

import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash, session

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
from tacacs_dashboard.services.access_control import allowed_device_group_ids

from tacacs_dashboard.services.user_secrets_store import (
    set_user_password,
    ensure_user_has_password,
    delete_user_password,
)

bp = Blueprint("users", __name__)


def _current_scope():
    """Return (role, web_username, allowed_group_ids).

    - superadmin -> allowed_group_ids is None (no scoping)
    - admin -> list of device group ids assigned in web_users.json
    """
    role = (session.get("web_role") or "admin").strip().lower()
    uname = (session.get("web_username") or "").strip()
    allowed_gids = allowed_device_group_ids(role, uname)
    return role, uname, allowed_gids


def _normalize_gid_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for g in value:
        gg = (g or "").strip().lower()
        if gg and gg not in out:
            out.append(gg)
    return out


def _user_in_scope(user: dict, allowed_gids) -> bool:
    """Admin can only manage TACACS users that are scoped to their device groups."""
    if allowed_gids is None:
        return True
    ugids = _normalize_gid_list(user.get("device_group_ids"))
    return any(g in set(allowed_gids) for g in ugids)


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


def _get_olt_ip_list(policy: dict, allowed_group_ids=None) -> list[str]:
    """
    คืน list ของ IP OLT ที่จะ provision/deprovision
    - ถ้ามี policy.devices -> ใช้ทุกตัวที่มี address/ip (แนะนำ filter Online)
    - ถ้าไม่มี -> ใช้ OLT_DEFAULT_IP (ถ้ามี)
    """
    ips: list[str] = []

    allowed_set = set(allowed_group_ids) if isinstance(allowed_group_ids, list) else None

    for d in (policy.get("devices") or []):
        # scope to device groups if requested
        if allowed_set is not None:
            gid = (d.get("group_id") or "").strip().lower()
            if not gid or gid not in allowed_set:
                continue
        st = (d.get("status") or "").strip().lower()
        if st and st not in ("online", "up"):
            continue

        ip = (d.get("address") or d.get("ip") or "").strip()
        if ip:
            ips.append(ip)

    # Only fall back to OLT_DEFAULT_IP when not scoped. If scoped, returning an
    # empty list is safer than provisioning to an unknown device.
    if not ips and allowed_set is None:
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


def _maybe_provision_to_olts(username: str, role: str, status: str, device_group_ids=None) -> None:
    # provision เฉพาะ Active
    if (status or "").strip().lower() not in ("active", "enable", "enabled"):
        return

    auto = (_read_env("OLT_AUTO_PROVISION", "0") or "0").strip().lower()
    if auto not in ("1", "true", "yes"):
        return

    policy = load_policy()
    olt_ips = _get_olt_ip_list(policy, allowed_group_ids=device_group_ids)
    if not olt_ips:
        if device_group_ids is not None:
            flash(
                "เปิด OLT_AUTO_PROVISION แต่ไม่พบ OLT (Online) ใน Device Group ที่กำหนดไว้ — โปรดตรวจสอบว่า OLT ใน group นั้นถูกเพิ่มใน Devices และสถานะเป็น Online",
                "warning",
            )
        else:
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


def _maybe_deprovision_from_olts(username: str, device_group_ids=None) -> None:
    auto = (_read_env("OLT_AUTO_DEPROVISION", "0") or "0").strip().lower()
    if auto not in ("1", "true", "yes"):
        return

    policy = load_policy()
    olt_ips = _get_olt_ip_list(policy, allowed_group_ids=device_group_ids)
    if not olt_ips:
        if device_group_ids is not None:
            flash(
                "เปิด OLT_AUTO_DEPROVISION แต่ไม่พบ OLT (Online) ใน Device Group ที่กำหนดไว้ — โปรดตรวจสอบว่า OLT ใน group นั้นถูกเพิ่มใน Devices และสถานะเป็น Online",
                "warning",
            )
        else:
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


def _maybe_deprovision_specific_ips(username: str, ips: list[str]) -> None:
    """Deprovision a user from a specific list of OLT IPs.

    Used when superadmin narrows a user's device-group scope and wants to remove
    the user's local stub from OLTs that are now out-of-scope.
    Guarded by OLT_AUTO_DEPROVISION.
    """
    if not ips:
        return

    auto = (_read_env("OLT_AUTO_DEPROVISION", "0") or "0").strip().lower()
    if auto not in ("1", "true", "yes"):
        return

    auto_write = (_read_env("OLT_AUTO_WRITE", "0") or "0").strip().lower()
    save = auto_write in ("1", "true", "yes")

    uniq: list[str] = []
    for ip in ips:
        ip2 = (ip or "").strip()
        if ip2 and ip2 not in uniq:
            uniq.append(ip2)

    for ip in uniq:
        try:
            out = deprovision_user_on_olt(
                ip,
                username=username,
                save=save,
                dry_run=False,
            )
            msg = _olt_job_summary(out, ip)
            flash(
                f"Deprovision (out-of-scope) '{username}' -> OLT {ip} สำเร็จ (save={'ON' if save else 'OFF'}): {msg}",
                "success",
            )
        except Exception as e:
            flash(f"Deprovision (out-of-scope) '{username}' -> OLT {ip} ล้มเหลว: {e}", "error")


# -----------------------
# Pages
# -----------------------
@bp.route("/")
def index():
    policy = load_policy()
    users = policy.get("users", [])
    roles = policy.get("roles", [])

    device_groups = policy.get("device_groups", []) or []
    # map group_id -> display name
    group_name_map = {}
    for g in device_groups:
        if not isinstance(g, dict):
            continue
        gid = (g.get("id") or g.get("group_id") or "").strip().lower()
        if not gid:
            continue
        nm = (g.get("name") or "").strip()
        group_name_map[gid] = nm

    # Scope admin view to device groups (users without device_group_ids are treated as out of scope)
    _role, _web_uname, allowed_gids = _current_scope()
    is_superadmin = (_role == "superadmin")
    if allowed_gids is not None:
        if not allowed_gids:
            flash("บัญชี admin นี้ยังไม่ได้ถูกกำหนด Device Group — กรุณาให้ superadmin กำหนดก่อน", "warning")
        users = [u for u in users if isinstance(u, dict) and _user_in_scope(u, allowed_gids)]

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


    
    # For UI: show device group labels (superadmin view)
    if is_superadmin:
        for u in users:
            if not isinstance(u, dict):
                continue
            ugids = _normalize_gid_list(u.get("device_group_ids"))
            if not ugids:
                u["device_groups_label"] = "All (unscoped)"
            else:
                parts = []
                for gid in ugids:
                    nm = group_name_map.get(gid) or ""
                    parts.append(f"{nm} ({gid})" if nm else gid)
                u["device_groups_label"] = ", ".join(parts)

    # --- UI sort: group -> username (so new users appear within their group) ---
    def _primary_gid(u: dict) -> str:
        ugids = _normalize_gid_list(u.get("device_group_ids"))
        return ugids[0] if ugids else ""   # "" = unscoped

    def _user_sort_key(u):
        if not isinstance(u, dict):
            return (1, "zzzz", "zzzz", "zzzz")
        uname = (u.get("username") or u.get("name") or "").strip().lower()

        gid = _primary_gid(u).lower()
        unscoped = 1 if not gid else 0     # ให้ unscoped ไปอยู่ท้ายสุด
        gname = (group_name_map.get(gid) or "").strip().lower()

        # เรียง: scoped ก่อน -> ชื่อ group -> gid -> username
        return (unscoped, gname or gid, gid, uname)

    users.sort(key=_user_sort_key)


    return render_template(
        "users.html",
        users=users,
        roles=roles,
        device_groups=device_groups,
        is_superadmin=is_superadmin,
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

    # Prevent creating usernames that clash with vendor/local accounts on OLT (e.g., 'zte')
    if is_reserved_olt_username(username):
        flash(f"ไม่อนุญาตให้ใช้ Username '{username}' (ถูกสงวนไว้/อาจชนกับ local user บน OLT)", "error")
        return redirect(url_for("users.index"))

    # ✅ Scope: admin สามารถสร้าง user ได้เฉพาะใน OLT ที่อยู่ใน Device Group ของตัวเองเท่านั้น
    _role, _web_uname, allowed_gids = _current_scope()
    is_superadmin = (_role == "superadmin")

    # device group scoping for TACACS users:
    # - admin: forced to their own allowed_gids
    # - superadmin: can optionally set device_group_ids (empty/unscoped = all OLTs)
    device_group_ids = None

    if allowed_gids is not None:
        # web admin
        if not allowed_gids:
            flash("บัญชี admin นี้ยังไม่ได้ถูกกำหนด Device Group — กรุณาให้ superadmin กำหนดก่อน", "error")
            return redirect(url_for("users.index"))
        device_group_ids = allowed_gids
    else:
        # superadmin (optional selection from form)
        unscoped = (request.form.get("unscoped") or "").strip().lower() in ("1", "true", "yes", "on")
        selected = _normalize_gid_list(request.form.getlist("device_group_ids"))

        if not unscoped and not selected:
            flash("กรุณาเลือก Device Group อย่างน้อย 1 กลุ่ม หรือเลือก Unscoped", "error")
            return redirect(url_for("users.index"))

        if not unscoped and selected:
            # validate against existing device groups
            valid_set = set()
            for g in (load_policy().get("device_groups") or []):
                if isinstance(g, dict):
                    gid = (g.get("id") or g.get("group_id") or "").strip().lower()
                    if gid:
                        valid_set.add(gid)
            selected = [g for g in selected if g in valid_set] if valid_set else selected
            if not selected:
                flash("กรุณาเลือก Device Group อย่างน้อย 1 กลุ่ม หรือเลือก Unscoped", "error")
                return redirect(url_for("users.index"))
            device_group_ids = selected

    policy = load_policy()
    users = policy.get("users", [])
    roles = policy.get("roles", [])
    role_names = {r.get("name") for r in roles if r.get("name")}

    if role_names and role not in role_names:
        flash(f"Role {role} ไม่มีอยู่ในระบบ", "error")
        return redirect(url_for("users.index"))

    if any((u.get("username") or "").strip() == username for u in users if isinstance(u, dict)):
        flash(f"User {username} มีอยู่แล้ว", "error")
        return redirect(url_for("users.index"))

    upsert_user(username=username, role=role, status=status, device_group_ids=device_group_ids)
    flash(f"เพิ่มผู้ใช้ {username} เรียบร้อย", "success")

    if password:
        set_user_password(username, password)
    else:
        ensure_user_has_password(username)

    ok = _run_generate_check_restart_and_flash()
    if ok:
        _maybe_provision_to_olts(username=username, role=role, status=status, device_group_ids=device_group_ids)

    return redirect(url_for("users.index"))


@bp.post("/delete/<username>")
def delete_user_form(username: str):
    username = (username or "").strip()
    if not username:
        flash("username ไม่ถูกต้อง", "error")
        return redirect(url_for("users.index"))

    policy = load_policy()
    users = policy.get("users", [])
    target = None
    for u in users:
        if isinstance(u, dict) and (u.get("username") or "").strip() == username:
            target = u
            break

    if not target:
        flash(f"ไม่พบผู้ใช้ {username}", "error")
        return redirect(url_for("users.index"))

    # ✅ Scope check: admin ลบได้เฉพาะ user ที่อยู่ใน device groups ของตัวเอง
    _role, _web_uname, allowed_gids = _current_scope()
    if allowed_gids is not None and not _user_in_scope(target, allowed_gids):
        flash("คุณไม่มีสิทธิ์ลบผู้ใช้นี้ (อยู่นอก Device Group ของคุณ)", "error")
        return redirect(url_for("users.index"))

    user_gids = _normalize_gid_list(target.get("device_group_ids"))

    ok = delete_user(username)
    if not ok:
        flash(f"ไม่พบผู้ใช้ {username}", "error")
        return redirect(url_for("users.index"))

    flash(f"ลบผู้ใช้ {username} เรียบร้อย", "success")

    delete_user_password(username)

    ok2 = _run_generate_check_restart_and_flash()
    if ok2:
        _maybe_deprovision_from_olts(username, device_group_ids=user_gids if user_gids else None)

    return redirect(url_for("users.index"))


@bp.get("/edit/<username>")
def edit_user_form(username):
    policy = load_policy()
    users = policy.get("users", [])
    roles = policy.get("roles", [])

    device_groups = policy.get("device_groups", []) or []

    target = None
    for u in users:
        if isinstance(u, dict) and (u.get("username") or "").strip() == (username or "").strip():
            target = u
            break

    if not target:
        flash(f"ไม่พบผู้ใช้ {username}", "error")
        return redirect(url_for("users.index"))

    # ✅ Scope check: admin แก้ไขได้เฉพาะ user ใน Device Group ของตัวเอง
    _role, _web_uname, allowed_gids = _current_scope()
    is_superadmin = (_role == "superadmin")
    if allowed_gids is not None and not _user_in_scope(target, allowed_gids):
        flash("คุณไม่มีสิทธิ์แก้ไขผู้ใช้นี้ (อยู่นอก Device Group ของคุณ)", "error")
        return redirect(url_for("users.index"))

    current_role = target.get("roles") or target.get("role") or ""
    selected_device_group_ids = _normalize_gid_list(target.get("device_group_ids"))

    return render_template(
        "user_edit.html",
        active_page="users",
        user=target,
        roles=roles,
        device_groups=device_groups,
        selected_device_group_ids=selected_device_group_ids,
        is_superadmin=is_superadmin,
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
    users = policy.get("users", [])
    roles = policy.get("roles", [])

    target = None
    for u in users:
        if isinstance(u, dict) and (u.get("username") or "").strip() == username:
            target = u
            break

    if not target:
        flash(f"ไม่พบผู้ใช้ {username}", "error")
        return redirect(url_for("users.index"))

    existing_gids = _normalize_gid_list(target.get("device_group_ids"))

    # ✅ Scope check (admin)
    _role, _web_uname, allowed_gids = _current_scope()
    is_superadmin = (_role == "superadmin")

    # device_group_ids update:
    # - admin: cannot change scope; if user is unscoped, it will be scoped to admin's groups on first edit
    # - superadmin: can assign/clear device_group_ids from Edit UI
    device_group_ids_to_set = None

    if allowed_gids is not None:
        # web admin scope check
        if not _user_in_scope(target, allowed_gids):
            flash("คุณไม่มีสิทธิ์แก้ไขผู้ใช้นี้ (อยู่นอก Device Group ของคุณ)", "error")
            return redirect(url_for("users.index"))
        # หาก user ยังไม่เคยถูก scope (ไม่มี device_group_ids) ให้ยึดตาม group ของ admin ปัจจุบัน
        device_group_ids_to_set = existing_gids or allowed_gids
    else:
        # superadmin: read from form
        unscoped = (request.form.get("unscoped") or "").strip().lower() in ("1", "true", "yes", "on")
        selected = _normalize_gid_list(request.form.getlist("device_group_ids"))

        if unscoped:
            device_group_ids_to_set = []  # clear => unscoped
        else:
            # validate group ids exist
            valid_set = set()
            for g in (policy.get("device_groups") or []):
                if isinstance(g, dict):
                    gid = (g.get("id") or g.get("group_id") or "").strip().lower()
                    if gid:
                        valid_set.add(gid)
            selected = [g for g in selected if g in valid_set] if valid_set else selected

            if not selected:
                flash("กรุณาเลือก Device Group อย่างน้อย 1 กลุ่ม หรือเลือก Unscoped", "error")
                return redirect(url_for("users.edit_user_form", username=username))
            device_group_ids_to_set = selected

    role_names = {r.get("name") for r in roles if r.get("name")}
    if role_names and new_role and new_role not in role_names:
        flash(f"Role {new_role} ไม่มีอยู่ในระบบ", "error")
        return redirect(url_for("users.edit_user_form", username=username))

    upsert_user(username=username, role=new_role, status=new_status, device_group_ids=device_group_ids_to_set)
    flash(f"อัปเดตผู้ใช้ {username} เรียบร้อยแล้ว", "success")

    ok = _run_generate_check_restart_and_flash()
    if ok:
        # If superadmin changed scoping to be narrower, optionally deprovision from out-of-scope OLTs
        if allowed_gids is None and device_group_ids_to_set is not None:
            new_gids = _normalize_gid_list(device_group_ids_to_set)
            old_gids = existing_gids

            # only when new scope is explicitly set (non-empty) -> remove access from outside
            if new_gids:
                all_ips = _get_olt_ip_list(policy, allowed_group_ids=None if not old_gids else old_gids)
                in_scope_ips = _get_olt_ip_list(policy, allowed_group_ids=new_gids)

                out_scope = [ip for ip in all_ips if ip not in set(in_scope_ips)]
                _maybe_deprovision_specific_ips(username, out_scope)

        provision_gids = device_group_ids_to_set if device_group_ids_to_set is not None else existing_gids
        _maybe_provision_to_olts(username=username, role=new_role, status=new_status, device_group_ids=provision_gids if provision_gids else None)

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



