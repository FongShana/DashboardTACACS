import re
import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash, session

from tacacs_dashboard.services.policy_store import load_policy, save_policy, update_policy
from tacacs_dashboard.services.tacacs_config import _read_env
from tacacs_dashboard.services.olt_status import get_olt_status, status_label
from tacacs_dashboard.services.tacacs_apply import apply_tacacs_config
from tacacs_dashboard.services.olt_bootstrap import bootstrap_device_on_olt
from tacacs_dashboard.services.access_control import allowed_device_group_ids, device_in_scope
from tacacs_dashboard.services.device_groups_store import list_device_groups, get_group_name_map, group_exists

bp = Blueprint("devices", __name__)

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,31}$")

def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    return all(0 <= n <= 255 for n in nums)


def _current_scope():
    role = (session.get("web_role") or "admin").strip().lower()
    uname = (session.get("web_username") or "").strip()
    allowed_gids = allowed_device_group_ids(role, uname)
    return role, uname, allowed_gids


# -----------------------
# Helpers: generate/check/restart (for devices flow)
# -----------------------
def _restart_tac_plus_ng() -> tuple[bool, str]:
    """Restart tac_plus-ng via systemd.

    Requires sudoers to allow the web user to run systemctl restart without
    password.
    """
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
    """Generate -> syntax check -> restart tac_plus-ng (serialized)."""
    r = apply_tacacs_config()
    path = r.get("config_path", "?")
    line_count = r.get("line_count", 0)
    check_ok = bool(r.get("check_ok"))
    check_msg = (r.get("check_message") or "").strip()
    restart_ok = bool(r.get("restart_ok"))
    restart_msg = (r.get("restart_message") or "").strip()

    short_check = check_msg if len(check_msg) <= 400 else check_msg[:400] + " ... (truncated)"
    short_restart = restart_msg if len(restart_msg) <= 400 else restart_msg[:400] + " ... (truncated)"

    if not check_ok:
        flash(
            f"Generate config ที่ {path} แล้ว แต่ syntax check FAILED. Message: {short_check}",
            "error",
        )
        return False

    flash(
        f"Generate config สำเร็จ: {path} ({line_count} lines). Syntax check: OK. Message: {short_check}",
        "success",
    )

    if restart_ok:
        flash(f"Restart tac_plus-ng สำเร็จ: {short_restart}", "success")
        return True

    flash(f"Restart tac_plus-ng ล้มเหลว: {short_restart}", "error")
    return False




@bp.route("/")
def index():
    policy = load_policy()
    devices = policy.get("devices", [])
    groups = list_device_groups()
    group_map = get_group_name_map()

    role, uname, allowed_gids = _current_scope()
    if allowed_gids is not None:
        devices = [d for d in devices if isinstance(d, dict) and device_in_scope(d, allowed_gids)]
        groups = [g for g in groups if g.get("id") in set(allowed_gids)]

    # enrich for UI (do NOT persist status in policy.json)
    devices_ui = []
    for d in devices:
        if not isinstance(d, dict):
            continue
        ui = dict(d)

        gid = (ui.get("group_id") or "").strip()
        ui["group_id"] = gid
        ui["group_name"] = group_map.get(gid, "-") if gid else "-"

        ip = (ui.get("ip") or ui.get("address") or "").strip()
        # If device has not been bootstrapped yet, show Unknown (onboarding not complete)
        # Missing key => treat as already bootstrapped (backward compatible)
        if ui.get("bootstrap_done") is False:
            ui["status"] = "Unknown"
            ui["status_hint"] = "Not bootstrapped"
        else:
            ui["status"] = status_label(get_olt_status(ip))

        devices_ui.append(ui)

    return render_template(
        "devices.html",
        devices=devices_ui,
        device_groups=groups,
        is_scoped_admin=(allowed_gids is not None),
        active_page="devices",
    )



@bp.post("/create")
def create_device_form():
    name = request.form.get("name")
    ip = request.form.get("ip")
    vendor = request.form.get("vendor", "")
    group_id = (request.form.get("group_id") or "").strip().lower()
    # UX: "Add Device" should only add to policy.json.
    # Bootstrap is a separate explicit action (safer).

    if not name or not ip:
        flash("กรุณากรอก Name และ IP ให้ครบ", "error")
        return redirect(url_for("devices.index"))

    if not _is_valid_ipv4(ip):
        flash(f"IP {ip} ไม่ใช่ IPv4 ที่ถูกต้อง", "error")
        return redirect(url_for("devices.index"))

    role, uname, allowed_gids = _current_scope()
    if allowed_gids is not None:
        # admin must be assigned to at least one group
        if not allowed_gids:
            flash("บัญชี admin นี้ยังไม่ได้ถูกกำหนด Device Group — กรุณาให้ superadmin กำหนดก่อน", "error")
            return redirect(url_for("devices.index"))
        # admin must choose a group and it must be allowed
        if not group_id:
            flash("กรุณาเลือก Device Group ก่อนเพิ่มอุปกรณ์", "error")
            return redirect(url_for("devices.index"))
        if group_id not in set(allowed_gids):
            flash("คุณไม่มีสิทธิ์เพิ่มอุปกรณ์ใน group นี้", "error")
            return redirect(url_for("devices.index"))

    if group_id and not group_exists(group_id):
        flash("Device Group ไม่ถูกต้อง (ไม่พบใน policy.json)", "error")
        return redirect(url_for("devices.index"))

    try:
        def _mut(policy):
            devices = policy.get("devices", []) or []
            if not isinstance(devices, list):
                devices = []
            if any(isinstance(d, dict) and d.get("name") == name for d in devices):
                raise ValueError(f"Device {name} มีอยู่แล้ว")

            devices.append({
                "name": name,
                "vendor": vendor,
                "ip": ip,
                "group_id": group_id,
                # Mark as not bootstrapped yet (will show status=Unknown until bootstrap is done)
                "bootstrap_done": False,
            })
            policy["devices"] = devices

        update_policy(_mut)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("devices.index"))

    flash(f"เพิ่มอุปกรณ์ {name} เรียบร้อย", "success")

    # ✅ Reminder: TACACS config needs to be applied so the new OLT host/key is
    # known by tac_plus-ng. Bootstrap is a separate step.
    flash("หมายเหตุ: เพิ่ม Device แล้ว กรุณากด 'Generate & Apply TACACS Config' ก่อน จากนั้นค่อย Bootstrap AAA", "info")

    return redirect(url_for("devices.index"))


@bp.post("/generate-config")
def generate_config_submit():
    """Generate & apply TACACS config from Devices/OLT page."""
    _run_generate_check_restart_and_flash()
    return redirect(url_for("devices.index"))


@bp.post("/bootstrap/<name>")
def bootstrap_device_submit(name: str):
    """Explicit bootstrap action (recommended UX).

    - safe by default: dashboard does NOT perform `write` (persist) to OLT.
    - supports preview (dry-run) via button name="dry_run".
    """

    policy = load_policy()
    devices = policy.get("devices", [])
    dev = next((d for d in devices if (d.get("name") or "") == name), None)
    if not dev:
        flash(f"ไม่พบ Device {name}", "error")
        return redirect(url_for("devices.index"))

    role, uname, allowed_gids = _current_scope()
    if allowed_gids is not None and not device_in_scope(dev, allowed_gids):
        flash("คุณไม่มีสิทธิ์ Bootstrap อุปกรณ์นี้", "error")
        return redirect(url_for("devices.index"))

    ip = (dev.get("ip") or dev.get("address") or "").strip()
    if not ip:
        flash(f"Device {name} ไม่มี IP ใน policy.json", "error")
        return redirect(url_for("devices.index"))

    is_preview = (request.form.get("dry_run") or "").strip().lower() in ("1", "true", "yes", "on")

    # write is disabled from dashboard for safety (no 'save' option)
    save = False

    try:
        out = bootstrap_device_on_olt(ip, save=save, dry_run=is_preview)
        # flash needs to be reasonably small; keep the end of output (most useful)
        out = (out or "").strip()
        if len(out) > 2500:
            out = "... (truncated)\n" + out[-2400:]

        # Mark device as bootstrapped (persist in policy.json) — safe update under lock
        if not is_preview:
            def _mut(policy2):
                devices2 = policy2.get("devices", []) or []
                for dd in devices2:
                    if isinstance(dd, dict) and dd.get("name") == name:
                        dd["bootstrap_done"] = True
                        break
                policy2["devices"] = devices2

            update_policy(_mut)

        if is_preview:
            flash(f"Preview Bootstrap (no changes) for {name} ({ip})\n{out}", "info")
        else:
            flash(
                f"Bootstrap AAA on OLT {name} ({ip}) สำเร็จ\n{out}",
                "success",
            )
    except Exception as e:
        flash(f"Bootstrap AAA on OLT {name} ({ip}) ล้มเหลว: {e}", "error")

    return redirect(url_for("devices.index"))


@bp.post("/delete/<name>")
def delete_device_form(name):
    policy = load_policy()
    devices = policy.get("devices", [])

    role, uname, allowed_gids = _current_scope()
    if allowed_gids is not None:
        dev = next((d for d in devices if (d.get("name") or "") == name), None)
        if not dev or not device_in_scope(dev, allowed_gids):
            flash("คุณไม่มีสิทธิ์ลบอุปกรณ์นี้", "error")
            return redirect(url_for("devices.index"))

    new_devices = [d for d in devices if d.get("name") != name]
    if len(new_devices) == len(devices):
        flash(f"ไม่พบอุปกรณ์ {name}", "error")
        return redirect(url_for("devices.index"))

    def _mut(policy2):
        devices2 = policy2.get("devices", []) or []
        policy2["devices"] = [
            dd for dd in devices2
            if not (isinstance(dd, dict) and dd.get("name") == name)
        ]

    update_policy(_mut)

    flash(f"ลบอุปกรณ์ {name} เรียบร้อย", "success")
    return redirect(url_for("devices.index"))



@bp.get("/<name>/edit")
def edit_device_form(name):
    policy = load_policy()
    devices = policy.get("devices", [])

    target = None
    for d in devices:
        if d.get("name") == name:
            target = d
            break

    if not target:
        flash(f"ไม่พบ Device {name}", "error")
        return redirect(url_for("devices.index"))

    role, uname, allowed_gids = _current_scope()
    groups = list_device_groups()
    if allowed_gids is not None:
        if not device_in_scope(target, allowed_gids):
            flash("คุณไม่มีสิทธิ์แก้ไขอุปกรณ์นี้", "error")
            return redirect(url_for("devices.index"))
        groups = [g for g in groups if g.get("id") in set(allowed_gids)]

    return render_template(
        "device_edit.html",
        active_page="devices",
        device=target,
        device_groups=groups,
    )


@bp.post("/<name>/edit")
def edit_device_submit(name):
    policy = load_policy()
    devices = policy.get("devices", [])

    target = next((d for d in devices if (d.get("name") or "") == name), None)
    if not target:
        flash(f"ไม่พบ Device {name}", "error")
        return redirect(url_for("devices.index"))

    role, uname, allowed_gids = _current_scope()
    if allowed_gids is not None and not device_in_scope(target, allowed_gids):
        flash("คุณไม่มีสิทธิ์แก้ไขอุปกรณ์นี้", "error")
        return redirect(url_for("devices.index"))

    old_ip = (target.get("ip") or target.get("address") or "").strip()

    # --- ✅ rename ได้ ---
    new_name = (request.form.get("name") or "").strip() or name
    if new_name != name:
        if not NAME_RE.match(new_name):
            flash("Device name ต้องยาว 3–32 ตัว และใช้ได้เฉพาะ A-Z a-z 0-9 _ -", "error")
            return redirect(url_for("devices.edit_device_form", name=name))

        if any((d.get("name") or "").strip() == new_name for d in devices if d is not target):
            flash(f"ชื่อ Device '{new_name}' ซ้ำกับตัวอื่น", "error")
            return redirect(url_for("devices.edit_device_form", name=name))

        target["name"] = new_name

    # --- update other fields ---
    vendor = (request.form.get("vendor") or "").strip()
    ip = (request.form.get("ip") or "").strip()
    group_id = (request.form.get("group_id") or "").strip().lower()

    if ip and not _is_valid_ipv4(ip):
        flash(f"IP {ip} ไม่ใช่ IPv4 ที่ถูกต้อง", "error")
        return redirect(url_for("devices.edit_device_form", name=name))

    if allowed_gids is not None:
        if not allowed_gids:
            flash("บัญชี admin นี้ยังไม่ได้ถูกกำหนด Device Group — กรุณาให้ superadmin กำหนดก่อน", "error")
            return redirect(url_for("devices.index"))
        # admin must keep device in allowed groups
        if not group_id:
            flash("กรุณาเลือก Device Group", "error")
            return redirect(url_for("devices.edit_device_form", name=name))
        if group_id not in set(allowed_gids):
            flash("คุณไม่มีสิทธิ์ย้ายอุปกรณ์ไป group นี้", "error")
            return redirect(url_for("devices.edit_device_form", name=name))

    if group_id and not group_exists(group_id):
        flash("Device Group ไม่ถูกต้อง (ไม่พบใน policy.json)", "error")
        return redirect(url_for("devices.edit_device_form", name=name))

    # Apply update under lock on the latest policy to avoid lost updates (multi-user safe)
    def _mut(policy2):
        devices2 = policy2.get("devices", []) or []
        for dd in devices2:
            if isinstance(dd, dict) and dd.get("name") == name:
                dd["vendor"] = vendor
                if ip:
                    dd["ip"] = ip
                    # If IP changed, require re-bootstrap (new/changed device)
                    if ip.strip() and ip.strip() != (old_ip or "").strip():
                        dd["bootstrap_done"] = False
                # Stop storing status in policy.json (status is computed at runtime)
                dd.pop("status", None)
                dd["group_id"] = group_id
                break
        policy2["devices"] = devices2

    update_policy(_mut)
    flash("บันทึก Device สำเร็จ", "success")
    return redirect(url_for("devices.index"))



