import re
import subprocess
from datetime import datetime, timezone, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session

from tacacs_dashboard.services.policy_store import load_policy, update_policy
from tacacs_dashboard.services.tacacs_config import _read_env
from tacacs_dashboard.services.olt_status import get_olt_status, status_label
from tacacs_dashboard.services.tacacs_apply import generate_check_restart
from tacacs_dashboard.services.olt_bootstrap import bootstrap_device_on_olt
from tacacs_dashboard.services.access_control import allowed_device_group_ids, device_in_scope
from tacacs_dashboard.services.device_groups_store import list_device_groups, get_group_name_map, group_exists

bp = Blueprint("devices", __name__)

NAME_RE = re.compile(r"^[^\W\d_][\w\-\u0E31-\u0E4E]{2,31}$", re.UNICODE)


def _now_iso() -> str:
    """Return ISO timestamp (seconds precision) for policy.json metadata fields."""
    return datetime.now().replace(microsecond=0).isoformat()


# Display timezone for dashboard UI (Bangkok / UTC+07)
_BKK_TZ = timezone(timedelta(hours=7))


def _fmt_ts_bkk(ts: str | None) -> str | None:
    """Format an ISO timestamp (stored in policy.json) as Bangkok time.

    Notes:
      - Existing metadata fields may be naive (no tzinfo). Treat them as UTC.
      - If a tz offset exists, convert to UTC+07.
    """
    if not ts:
        return None
    s = (ts or "").strip()
    if not s:
        return None
    # Support ISO with trailing 'Z'
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    dt: datetime | None = None
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        # Fallback for legacy formats
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                dt = None

    if dt is None:
        return ts
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_BKK_TZ).strftime("%Y-%m-%d %H:%M:%S")

def _is_valid_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    return all(0 <= n <= 255 for n in nums)


def _normalize_ip(ip: str) -> str:
    return (ip or "").strip()


def _find_device_by_ip(devices: list, ip: str, *, exclude_name: str | None = None):
    """Return first device dict that matches IP (supports legacy 'address')."""
    nip = _normalize_ip(ip)
    if not nip:
        return None
    for d in devices or []:
        if not isinstance(d, dict):
            continue
        if exclude_name and (d.get("name") or "") == exclude_name:
            continue
        dip = _normalize_ip(d.get("ip") or d.get("address") or "")
        if dip and dip == nip:
            return d
    return None


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
    """Generate config + syntax check + restart tac_plus-ng (serialized).

    Used from Devices/OLT page so that after adding a new device, operator can
    explicitly apply config before bootstrapping.
    """
    result = generate_check_restart()

    # If another worker is already applying, we queue this request and return fast
    # (the lock owner will do a debounced final apply).
    if result.get("queued"):
        qmsg = (result.get("message") or "Apply is already running; queued.").strip()
        flash(f"Apply กำลังทำงานอยู่แล้ว ระบบรับคำขอ Apply เข้าคิวแล้ว: {qmsg}", "info")
        return False

    rerun_count = int(result.get("rerun_count") or 0)
    if rerun_count > 0 or result.get("coalesced"):
        flash(
            f"มีคำขอ Apply เข้ามาระหว่างทำงาน ระบบจึงรวมคำขอและ Apply รอบสรุปให้อีกครั้ง (debounce). rerun={rerun_count}",
            "info",
        )
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

        # Display timestamps in Bangkok timezone
        if ui.get("created_at"):
            ui["created_at"] = _fmt_ts_bkk(ui.get("created_at")) or ui.get("created_at")
        if ui.get("updated_at"):
            ui["updated_at"] = _fmt_ts_bkk(ui.get("updated_at")) or ui.get("updated_at")

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
    name = (request.form.get("name") or "").strip()
    ip = (request.form.get("ip") or "").strip()
    vendor = (request.form.get("vendor", "") or "").strip()
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
            devices = policy.get("devices", [])
            if not isinstance(devices, list):
                devices = []
            if any(isinstance(d, dict) and d.get("name") == name for d in devices):
                raise ValueError(f"Device {name} มีอยู่แล้ว")

            dup = _find_device_by_ip(devices, ip)
            if dup is not None:
                # Don't leak other groups/devices to scoped admins.
                if (session.get("web_role") or "admin").strip().lower() == "superadmin":
                    raise ValueError(
                        f"IP {ip} ถูกใช้งานแล้วในระบบ (device: {(dup.get('name') or '').strip() or '-'})."
                    )
                raise ValueError(f"IP {ip} ถูกใช้งานแล้วในระบบ")

            now = _now_iso()
            devices.append({
                "name": name,
                "vendor": vendor,
                "ip": ip,
                "group_id": group_id,
                # Mark as not bootstrapped yet (will show status=Unknown until bootstrap is done)
                "bootstrap_done": False,
                # Metadata for dashboard display
                "created_at": now,
                "updated_at": now,
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

        # Mark device as bootstrapped (persist in policy.json)
        if not is_preview:
            try:
                def _mut(policy2):
                    devices2 = policy2.get("devices", [])
                    if not isinstance(devices2, list):
                        raise ValueError("devices is not a list")
                    for d in devices2:
                        if isinstance(d, dict) and (d.get("name") or "") == name:
                            d["bootstrap_done"] = True
                            return
                    raise ValueError(f"ไม่พบ Device {name} ใน policy.json (ระหว่างบันทึก bootstrap_done)")

                update_policy(_mut)
            except Exception as e:
                flash(f"บันทึกสถานะ bootstrap_done ล้มเหลว: {e}", "error")

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

    try:
        def _mut(policy2):
            devices2 = policy2.get("devices", [])
            if not isinstance(devices2, list):
                devices2 = []
            new_devices = [d for d in devices2 if not (isinstance(d, dict) and d.get("name") == name)]
            if len(new_devices) == len(devices2):
                raise ValueError(f"ไม่พบอุปกรณ์ {name}")
            policy2["devices"] = new_devices

        update_policy(_mut)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("devices.index"))

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

    # Prevent duplicate IP across all devices.
    # (Don't leak other groups/devices to scoped admins.)
    if ip and ip.strip() and ip.strip() != (old_ip or "").strip():
        dup = _find_device_by_ip(devices, ip, exclude_name=name)
        if dup is not None:
            if role == "superadmin":
                flash(
                    f"IP {ip} ถูกใช้งานแล้วในระบบ (device: {(dup.get('name') or '').strip() or '-'}).",
                    "error",
                )
            else:
                flash(f"IP {ip} ถูกใช้งานแล้วในระบบ", "error")
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

    target["vendor"] = vendor
    if ip:
        target["ip"] = ip
        # If IP changed, require re-bootstrap (new/changed device)
        if ip.strip() and ip.strip() != (old_ip or "").strip():
            target["bootstrap_done"] = False

    # Stop storing status in policy.json (status is computed at runtime)
    target.pop("status", None)
    target["group_id"] = group_id

    try:
        def _mut(policy2):
            devices2 = policy2.get("devices", [])
            if not isinstance(devices2, list):
                raise ValueError("devices is not a list")

            target2 = next((d for d in devices2 if isinstance(d, dict) and (d.get("name") or "") == name), None)
            if not target2:
                raise ValueError(f"ไม่พบ Device {name}")

            # rename (re-check uniqueness under lock)
            if new_name != name:
                if any(isinstance(d, dict) and (d.get("name") or "").strip() == new_name for d in devices2 if d is not target2):
                    raise ValueError(f"ชื่อ Device '{new_name}' ซ้ำกับตัวอื่น")
                target2["name"] = new_name

            target2["vendor"] = vendor
            if ip:
                # Re-check under lock to avoid race conditions.
                dup2 = _find_device_by_ip(devices2, ip, exclude_name=name)
                if dup2 is not None:
                    if (session.get("web_role") or "admin").strip().lower() == "superadmin":
                        raise ValueError(
                            f"IP {ip} ถูกใช้งานแล้วในระบบ (device: {(dup2.get('name') or '').strip() or '-'})."
                        )
                    raise ValueError(f"IP {ip} ถูกใช้งานแล้วในระบบ")
                target2["ip"] = ip
                if ip.strip() and ip.strip() != (old_ip or "").strip():
                    target2["bootstrap_done"] = False

            # Stop storing status in policy.json (status is computed at runtime)
            target2.pop("status", None)
            target2["group_id"] = group_id

            # Metadata for dashboard display
            now = _now_iso()
            if not (target2.get("created_at") or "").strip():
                # Backward compatible for older entries that didn't track timestamps.
                target2["created_at"] = now
            target2["updated_at"] = now

        update_policy(_mut)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("devices.edit_device_form", name=name))

    flash("บันทึก Device สำเร็จ", "success")
    return redirect(url_for("devices.index"))


