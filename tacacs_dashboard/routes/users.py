# tacacs_dashboard/routes/users.py
from __future__ import annotations

import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash, session

import re
from tacacs_dashboard.services.log_parser import get_last_login_map
from tacacs_dashboard.services.privilege import parse_privilege

from tacacs_dashboard.services.policy_store import (
    load_policy,
    update_policy,
    upsert_user,
    delete_user,
    is_reserved_olt_username,
)
from tacacs_dashboard.services.tacacs_config import _read_env
from tacacs_dashboard.services.tacacs_apply import generate_check_restart
from tacacs_dashboard.services.olt_provision import provision_user_on_olt, deprovision_user_on_olt
from tacacs_dashboard.services.olt_status import get_olt_status
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


def _get_provision_user() -> str:
    """Provisioning service-account username from secret.env (default: tac_prov)."""
    u = (_read_env("OLT_PROVISION_USER", "tac_prov") or "tac_prov").strip()
    return u or "tac_prov"


def _normalize_gid_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for g in value:
        gg = (g or "").strip().lower()
        if gg and gg not in out:
            out.append(gg)
    return out


def _normalize_ip_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for ip in value:
        ip2 = (ip or "").strip()
        if ip2 and ip2 not in out:
            out.append(ip2)
    return out


def _user_in_scope(user: dict, allowed_gids) -> bool:
    """Admin can only manage TACACS users that are scoped to their device groups."""
    if allowed_gids is None:
        return True
    ugids = _normalize_gid_list(user.get("device_group_ids"))
    return any(g in set(allowed_gids) for g in ugids)


def _group_name_map(policy: dict) -> dict[str, str]:
    device_groups = policy.get("device_groups") or []
    out: dict[str, str] = {}
    for g in device_groups:
        if not isinstance(g, dict):
            continue
        gid = (g.get("id") or g.get("group_id") or "").strip().lower()
        if not gid:
            continue
        nm = (g.get("name") or "").strip()
        if nm:
            out[gid] = nm
    return out


def _device_choices_for_ui(policy: dict, *, allowed_group_ids=None) -> list[dict]:
    """Return OLT choices for UI checkboxes (online only).

    Each item: {ip, name, group_id, group_label, status}
    """
    allowed_set = set(allowed_group_ids) if isinstance(allowed_group_ids, list) else None
    gmap = _group_name_map(policy)

    out: list[dict] = []
    for d in (policy.get("devices") or []):
        if not isinstance(d, dict):
            continue

        gid = (d.get("group_id") or "").strip().lower()
        if allowed_set is not None:
            if not gid or gid not in allowed_set:
                continue
        # Only consider bootstrapped devices (missing key => assume bootstrapped)
        if d.get("bootstrap_done") is False:
            continue

        ip = (d.get("address") or d.get("ip") or "").strip()
        if not ip:
            continue


        st = get_olt_status(ip)
        if st != "online":
            continue

        name = (d.get("name") or "").strip() or ip
        gnm = (gmap.get(gid) or "").strip()
        if gnm and gid:
            glabel = f"{gnm} ({gid})"
        else:
            glabel = gid or gnm or "-"

        out.append({
            "ip": ip,
            "name": name,
            "group_id": gid,
            "group_label": glabel,
            "status": st,
        })

    out.sort(key=lambda x: ((x.get("group_id") or ""), (x.get("name") or ""), (x.get("ip") or "")))
    return out


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
    1) generate devices.secret + pass.secret + tacacs-generated.cfg
    2) syntax check (-P)
    3) restart tac_plus-ng (ถ้า syntax OK)

    NOTE: This is serialized across Gunicorn workers via an inter-process lock.
    """
    result = generate_check_restart()
    path = result.get("config_path")
    line_count = int(result.get("line_count") or 0)

    ok = bool(result.get("syntax_ok"))
    message = (result.get("syntax_message") or "").strip()
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

    rok = bool(result.get("restart_ok"))
    rmsg = (result.get("restart_message") or "").strip()
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
        # Only consider bootstrapped devices (missing key => assume bootstrapped)
        if d.get("bootstrap_done") is False:
            continue

        ip = (d.get("address") or d.get("ip") or "").strip()
        if not ip:
            continue
        if get_olt_status(ip) != "online":
            continue

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


def _maybe_provision_to_olts(
    username: str,
    role: str,
    status: str,
    device_group_ids=None,
    target_olt_ips: list[str] | None = None,
) -> None:
    # provision เฉพาะ Active
    if (status or "").strip().lower() not in ("active", "enable", "enabled"):
        return

    auto = (_read_env("OLT_AUTO_PROVISION", "0") or "0").strip().lower()
    if auto not in ("1", "true", "yes"):
        return

    policy = load_policy()
    olt_ips = _get_olt_ip_list(policy, allowed_group_ids=device_group_ids)

    # If user picked a target subset, only provision to those IPs.
    if target_olt_ips:
        target_set = set(_normalize_ip_list(target_olt_ips))
        olt_ips = [ip for ip in olt_ips if ip in target_set]
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
    group_name_map = _group_name_map(policy)

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
                # legacy: device_group_ids ว่าง => เทียบเท่า all OLTs
                u["device_groups_label"] = "All OLTs"
            else:
                parts = []
                for gid in ugids:
                    nm = group_name_map.get(gid) or ""
                    parts.append(f"{nm} ({gid})" if nm else gid)
                u["device_groups_label"] = ", ".join(parts)

    # ✅ OLT choices for Add User form
    # - superadmin: all online OLTs
    # - admin: only online OLTs in their assigned device groups
    devices_for_form = _device_choices_for_ui(policy, allowed_group_ids=allowed_gids)


    # ✅ Sort users by Device Group (then Last/First/Username) for cleaner UX
    # - Uses device_groups order from policy.json as the primary ordering
    group_order: dict[str, int] = {}
    for i, g in enumerate(device_groups):
        gid = ""
        if isinstance(g, dict):
            gid = (g.get("id") or g.get("group_id") or "").strip().lower()
        else:
            gid = str(getattr(g, "id", "") or "").strip().lower()
        if gid and gid not in group_order:
            group_order[gid] = i


    # ✅ OLT choices for Add User form
    # - superadmin: all online OLTs
    # - admin: only online OLTs in their assigned device groups
    devices_for_form = _device_choices_for_ui(policy, allowed_group_ids=allowed_gids)


    # --- UI sort: Device Group -> Role -> Username ---
    prov_user = _get_provision_user().strip().lower()

    # Group order follows device_groups list order in policy.json (stable, user-friendly)
    group_order = {}
    for i, g in enumerate(device_groups):
        gid = (g.get("id") or "").strip().lower()
        if gid and gid not in group_order:
            group_order[gid] = i

    def _primary_gid(u: dict) -> str:
        ugids = _normalize_gid_list(u.get("device_group_ids"))
        return ugids[0] if ugids else ""   # "" = legacy/unscoped

    def _role_key(u: dict) -> str:
        r = (u.get("roles") or u.get("role") or u.get("group") or "").strip().lower()
        return r

    def _user_sort_key(u):
        # Always pin provisioning service-account to the top if present
        if not isinstance(u, dict):
            return (1, 9999, 1, "zzzz", "zzzz")

        uname = (u.get("username") or u.get("name") or "").strip().lower()
        if prov_user and uname == prov_user:
            return (0,)

        gid = _primary_gid(u).lower()
        unscoped = 1 if not gid else 0  # put legacy/unscoped at the end
        gidx = group_order.get(gid, 9999)
        role = _role_key(u)
        return (1, gidx, unscoped, role, uname)

    users.sort(key=_user_sort_key)


    return render_template(
        "users.html",
        provision_user=_get_provision_user(),
        users=users,
        roles=roles,
        device_groups=device_groups,
        devices=devices_for_form,
        is_superadmin=is_superadmin,
        active_page="users",
    )


# -----------------------
# Users form actions
# -----------------------
@bp.post("/create")
def create_user_form():
    username = (request.form.get("username") or "").strip()
    first_name = (request.form.get("first_name") or "").strip()
    last_name = (request.form.get("last_name") or "").strip()
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

    # Protect provisioning service-account name from secret.env (default: tac_prov)
    prov_user = _get_provision_user()
    if username.strip().lower() == prov_user.strip().lower():
        flash(f"ห้ามสร้าง Username '{username}' เพราะเป็นบัญชี provisioning ({prov_user})", "error")
        return redirect(url_for("users.index"))

    # ✅ Scope: admin สามารถสร้าง user ได้เฉพาะใน OLT ที่อยู่ใน Device Group ของตัวเองเท่านั้น
    _role, _web_uname, allowed_gids = _current_scope()
    is_superadmin = (_role == "superadmin")

    # device group scoping for TACACS users:
    # - admin: forced to their own allowed_gids
    # - superadmin: must assign at least 1 device group (ยกเลิกแนวคิด Unscoped)
    device_group_ids = None

    if allowed_gids is not None:
        # web admin
        if not allowed_gids:
            flash("บัญชี admin นี้ยังไม่ได้ถูกกำหนด Device Group — กรุณาให้ superadmin กำหนดก่อน", "error")
            return redirect(url_for("users.index"))
        device_group_ids = allowed_gids
    else:
        # superadmin: ต้องเลือก Device Group อย่างน้อย 1 กลุ่ม (ยกเลิกแนวคิด Unscoped)
        selected = _normalize_gid_list(request.form.getlist("device_group_ids"))
        if not selected:
            flash("กรุณาเลือก Device Group อย่างน้อย 1 กลุ่ม", "error")
            return redirect(url_for("users.index"))

        # validate against existing device groups
        valid_set = set()
        for g in (load_policy().get("device_groups") or []):
            if isinstance(g, dict):
                gid = (g.get("id") or g.get("group_id") or "").strip().lower()
                if gid:
                    valid_set.add(gid)
        selected = [g for g in selected if g in valid_set] if valid_set else selected
        if not selected:
            flash("กรุณาเลือก Device Group อย่างน้อย 1 กลุ่ม", "error")
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

    # Optional: target OLT subset (online only, must be inside assigned device groups)
    raw_target_ips = _normalize_ip_list(request.form.getlist("target_olt_ips"))
    allowed_ips = set(_get_olt_ip_list(policy, allowed_group_ids=device_group_ids))
    target_ips = [ip for ip in raw_target_ips if ip in allowed_ips]

    if raw_target_ips and not target_ips:
        flash("OLT ที่เลือกไม่อยู่ใน Device Group ที่กำหนด หรือ OLT ไม่ได้ Online — โปรดเลือกใหม่ (หรือไม่เลือกเลย = ทุก OLT ใน scope)", "error")
        return redirect(url_for("users.index"))
    if raw_target_ips and len(target_ips) != len(raw_target_ips):
        flash("บาง OLT ที่เลือกถูกตัดออก (อยู่นอก scope หรือ Offline) — ระบบจะใช้เฉพาะ OLT ที่ Online ใน scope เท่านั้น", "warning")

    upsert_user(
        username=username,
        role=role,
        status=status,
        device_group_ids=device_group_ids,
        target_olt_ips=target_ips,
        first_name=first_name,
        last_name=last_name,
    )
    flash(f"เพิ่มผู้ใช้ {username} เรียบร้อย", "success")

    if password:
        set_user_password(username, password)
    else:
        ensure_user_has_password(username)

    ok = _run_generate_check_restart_and_flash()
    if ok:
        _maybe_provision_to_olts(
            username=username,
            role=role,
            status=status,
            device_group_ids=device_group_ids,
            target_olt_ips=target_ips if target_ips else None,
        )

    return redirect(url_for("users.index"))


@bp.post("/delete/<username>")
def delete_user_form(username: str):
    username = (username or "").strip()
    if not username:
        flash("username ไม่ถูกต้อง", "error")
        return redirect(url_for("users.index"))

    prov_user = _get_provision_user()
    if username.lower() == prov_user.lower():
        flash(f"ห้ามลบบัญชี provisioning ({prov_user})", "error")
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

    # For Edit UI: show only online OLTs in user's scope
    choice_scope_gids = None if is_superadmin else selected_device_group_ids
    devices_for_form = _device_choices_for_ui(policy, allowed_group_ids=choice_scope_gids)
    selected_target_olt_ips = _normalize_ip_list(target.get("target_olt_ips"))

    return render_template(
        "user_edit.html",
        provision_user=_get_provision_user(),
        active_page="users",
        user=target,
        roles=roles,
        device_groups=device_groups,
        devices=devices_for_form,
        selected_device_group_ids=selected_device_group_ids,
        selected_target_olt_ips=selected_target_olt_ips,
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

    # Optional fields (backward compatible)
    new_first_name = (request.form.get("first_name") or "").strip()
    new_last_name = (request.form.get("last_name") or "").strip()

    new_password = (request.form.get("password") or "").strip()

    prov_user = _get_provision_user()
    is_prov = (username or "").strip().lower() == prov_user.lower()

    # Protect provisioning account: disallow password changes
    if is_prov and new_password:
        flash("บัญชี provisioning ถูกล็อก: ไม่อนุญาตให้เปลี่ยน password", "warning")
        new_password = ""

    if new_password and not is_prov:
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
    existing_target_ips = _normalize_ip_list(target.get("target_olt_ips"))

    # ✅ Scope check (admin)
    _role, _web_uname, allowed_gids = _current_scope()
    is_superadmin = (_role == "superadmin")


    current_role = (target.get("roles") or target.get("role") or target.get("group") or "").strip() or "OLT_VIEW"
    current_status = (target.get("status") or "Active").strip() or "Active"

    # Protect provisioning account: disallow role/status/scope changes (role/status/device_group_ids/target_olt_ips)
    if is_prov:
        # Role
        if new_role and new_role != current_role:
            flash("บัญชี provisioning ถูกล็อก: ไม่อนุญาตให้เปลี่ยน role", "warning")
        new_role = current_role

        # Status
        if new_status and (new_status.strip().lower() != current_status.strip().lower()):
            flash("บัญชี provisioning ถูกล็อก: ไม่อนุญาตให้เปลี่ยน status", "warning")
        new_status = current_status

        # Scope: only warn if the field exists in the submitted form (prevents false warnings for admin UI)
        if "device_group_ids" in request.form:
            form_gids = _normalize_gid_list(request.form.getlist("device_group_ids"))
            if form_gids != existing_gids:
                flash("บัญชี provisioning ถูกล็อก: ไม่อนุญาตให้เปลี่ยน device group scope", "warning")

        if "target_olt_ips" in request.form:
            form_ips = _normalize_ip_list(request.form.getlist("target_olt_ips"))
            if set(form_ips) != set(existing_target_ips):
                flash("บัญชี provisioning ถูกล็อก: ไม่อนุญาตให้เปลี่ยน target OLT scope", "warning")
    # device_group_ids update:
    # - admin: cannot change scope; if user has no device_group_ids, it will be scoped to admin's groups on first edit
    # - superadmin: must assign at least 1 device group (ยกเลิกแนวคิด Unscoped)
    # - provisioning user: scope is immutable
    if is_prov:
        device_group_ids_to_set = existing_gids
    elif allowed_gids is not None:
        # web admin scope check
        if not _user_in_scope(target, allowed_gids):
            flash("คุณไม่มีสิทธิ์แก้ไขผู้ใช้นี้ (อยู่นอก Device Group ของคุณ)", "error")
            return redirect(url_for("users.index"))
        # หาก user ยังไม่เคยถูก scope (ไม่มี device_group_ids) ให้ยึดตาม group ของ admin ปัจจุบัน
        device_group_ids_to_set = existing_gids or allowed_gids
    else:
        # superadmin: read from form (ต้องเลือกอย่างน้อย 1 group)
        selected = _normalize_gid_list(request.form.getlist("device_group_ids"))

        # validate group ids exist
        valid_set = set()
        for g in (policy.get("device_groups") or []):
            if isinstance(g, dict):
                gid = (g.get("id") or g.get("group_id") or "").strip().lower()
                if gid:
                    valid_set.add(gid)
        selected = [g for g in selected if g in valid_set] if valid_set else selected

        if not selected:
            flash("กรุณาเลือก Device Group อย่างน้อย 1 กลุ่ม", "error")
            return redirect(url_for("users.edit_user_form", username=username))
        device_group_ids_to_set = selected

    # Optional: target OLT subset (online only, must be inside assigned device groups)
    if is_prov:
        target_ips = existing_target_ips
    else:
        raw_target_ips = _normalize_ip_list(request.form.getlist("target_olt_ips"))
        allowed_ips = set(_get_olt_ip_list(policy, allowed_group_ids=device_group_ids_to_set))
        target_ips = [ip for ip in raw_target_ips if ip in allowed_ips]

        if raw_target_ips and not target_ips:
            flash("OLT ที่เลือกไม่อยู่ใน Device Group ที่กำหนด หรือ OLT ไม่ได้ Online — โปรดเลือกใหม่ (หรือไม่เลือกเลย = ทุก OLT ใน scope)", "error")
            return redirect(url_for("users.edit_user_form", username=username))
        if raw_target_ips and len(target_ips) != len(raw_target_ips):
            flash("บาง OLT ที่เลือกถูกตัดออก (อยู่นอก scope หรือ Offline) — ระบบจะใช้เฉพาะ OLT ที่ Online ใน scope เท่านั้น", "warning")

    role_names = {r.get("name") for r in roles if r.get("name")}
    if role_names and new_role and new_role not in role_names:
        flash(f"Role {new_role} ไม่มีอยู่ในระบบ", "error")
        return redirect(url_for("users.edit_user_form", username=username))

    upsert_user(
        username=username,
        role=new_role,
        status=new_status,
        device_group_ids=device_group_ids_to_set,
        target_olt_ips=target_ips,
        first_name=new_first_name,
        last_name=new_last_name,
    )
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

        # If user sets a target subset, enforce it by removing local stub from other in-scope OLTs.
        # (Guarded by OLT_AUTO_DEPROVISION)
        if (new_status or "").strip().lower() in ("active", "enable", "enabled") and target_ips:
            scope_ips = _get_olt_ip_list(policy, allowed_group_ids=provision_gids if provision_gids else None)
            to_remove = [ip for ip in scope_ips if ip not in set(target_ips)]
            _maybe_deprovision_specific_ips(username, to_remove)

        _maybe_provision_to_olts(
            username=username,
            role=new_role,
            status=new_status,
            device_group_ids=provision_gids if provision_gids else None,
            target_olt_ips=target_ips if target_ips else None,
        )

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

    desc = (request.form.get("description") or "").strip()

    # privilege validation: must be 1..15
    priv_raw = (request.form.get("privilege") or "").strip()
    if not re.search(r"\d+", priv_raw):
        flash("Privilege ต้องเป็นตัวเลข 1-15", "error")
        return redirect(url_for("users.edit_role_form", name=name))

    priv = parse_privilege(priv_raw, default=15)

    try:
        def _mut(policy):
            roles = policy.get("roles", [])
            if not isinstance(roles, list):
                raise ValueError("roles ใน policy.json ไม่ถูกต้อง (ควรเป็น list)")

            target = None
            for r in roles:
                if isinstance(r, dict) and (r.get("name") or "").strip() == name:
                    target = r
                    break
            if not target:
                raise ValueError(f"ไม่พบ Role {name}")

            target["description"] = desc
            target["privilege"] = str(priv)
            policy["roles"] = roles

        update_policy(_mut)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("users.index"))

    flash(f"อัปเดต Role {name} เรียบร้อยแล้ว", "success")
    _run_generate_check_restart_and_flash()
    return redirect(url_for("users.index"))

# -----------------------
# Emergency: switch local 'zte' user template (1 <-> 128)
# -----------------------
@bp.post("/zte-template-switch")
def zte_template_switch():
    """Switch local 'zte' system-user bind templates on a specific OLT.

    - to128: bind auth/author template 128 (zte cannot login when TACACS is up)
    - to1  : bind auth/author template 1   (local/break-glass)
    """
    role, web_uname, allowed_gids = _current_scope()
    if role != "superadmin":
        flash("Emergency (zte template) ใช้ได้เฉพาะ superadmin เท่านั้น", "error")
        return redirect(url_for("users.index", tab="overview"))

    olt_ip = (request.form.get("olt_ip") or "").strip()
    mode = (request.form.get("mode") or "").strip()
    if not olt_ip:
        flash("กรุณาเลือก OLT IP", "error")
        return redirect(url_for("users.index", tab="zte"))
    if mode not in ("to128", "to1"):
        flash("โหมดไม่ถูกต้อง", "error")
        return redirect(url_for("users.index", tab="zte"))

    target_tpl = "128" if mode == "to128" else "1"

    # Validate selected OLT exists in policy and is in scope
    policy = load_policy()
    devices = policy.get("devices", []) or []
    dev = next((d for d in devices if isinstance(d, dict) and str(d.get("ip") or "").strip() == olt_ip), None)
    if not dev:
        flash(f"ไม่พบ OLT {olt_ip} ใน policy.json", "error")
        return redirect(url_for("users.index", tab="zte"))

    gid = str(dev.get("group_id") or dev.get("device_group_id") or "").strip()
    if allowed_gids is not None and gid and gid not in allowed_gids:
        flash("คุณไม่มีสิทธิ์จัดการ OLT ใน group นี้", "error")
        return redirect(url_for("users.index", tab="zte"))

    # Prefer TACACS provisioning account if configured; fallback to legacy local admin (zte)
    prov_user = (_read_env("OLT_PROVISION_USER", "") or "").strip()
    prov_pass = (_read_env("OLT_PROVISION_PASSWORD", "") or "").strip()

    admin_user = (_read_env("OLT_ADMIN_USER", "zte") or "zte").strip()
    admin_pass = (
        (_read_env("OLT_ADMIN_PASS", "") or "")
        or (_read_env("OLT_ADMIN_PASSWORD", "") or "")
    ).strip()

    # Commands: do NOT 'write' (user will save manually if needed)
    cmds = [
        "conf t",
        "system-user",
        "user-name zte",
        f"bind authentication-template {target_tpl}",
        f"bind authorization-template {target_tpl}",
        "exit",
        "end",
    ]

    from tacacs_dashboard.services.olt_telnet import telnet_exec_commands

    # Try provisioning creds first (if set), then fallback to local admin
    last_err = None
    if prov_user and prov_pass:
        try:
            telnet_exec_commands(olt_ip, commands=cmds, admin_user=prov_user, admin_pass=prov_pass, timeout=12)
            flash(f"Switch zte -> template {target_tpl} สำเร็จ (login: {prov_user})", "success")
            return redirect(url_for("users.index", tab="zte"))
        except Exception as e:
            last_err = e

    if admin_user and admin_pass:
        try:
            telnet_exec_commands(olt_ip, commands=cmds, admin_user=admin_user, admin_pass=admin_pass, timeout=12)
            flash(f"Switch zte -> template {target_tpl} สำเร็จ (login: {admin_user})", "success")
            return redirect(url_for("users.index", tab="zte"))
        except Exception as e:
            last_err = e

    if last_err:
        flash(f"Switch zte -> template {target_tpl} ล้มเหลว: {last_err}", "error")
    else:
        flash("ยังไม่ได้ตั้งค่า OLT login credentials (โปรดตั้ง OLT_PROVISION_* หรือ OLT_ADMIN_*)", "error")

    return redirect(url_for("users.index", tab="zte"))
