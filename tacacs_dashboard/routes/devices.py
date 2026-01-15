import re
import subprocess
from flask import Blueprint, render_template, request, redirect, url_for, flash

from tacacs_dashboard.services.policy_store import load_policy, save_policy
from tacacs_dashboard.services.tacacs_config import _read_env
from tacacs_dashboard.services.tacacs_apply import generate_config_file, check_config_syntax
from tacacs_dashboard.services.olt_bootstrap import bootstrap_device_on_olt

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
    """Generate config + syntax check + restart tac_plus-ng.

    Used from Devices/OLT page so that after adding a new device, operator can
    explicitly apply config before bootstrapping.
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


@bp.route("/")
def index():
    policy = load_policy()
    devices = policy.get("devices", [])
    return render_template(
        "devices.html",
        devices=devices,
        active_page="devices",
    )


@bp.post("/create")
def create_device_form():
    name = request.form.get("name")
    ip = request.form.get("ip")
    vendor = request.form.get("vendor", "")
    site = request.form.get("site", "")
    status = request.form.get("status", "Unknown")
    # UX: "Add Device" should only add to policy.json.
    # Bootstrap is a separate explicit action (safer).

    if not name or not ip:
        flash("กรุณากรอก Name และ IP ให้ครบ", "error")
        return redirect(url_for("devices.index"))

    if not _is_valid_ipv4(ip):
        flash(f"IP {ip} ไม่ใช่ IPv4 ที่ถูกต้อง", "error")
        return redirect(url_for("devices.index"))

    policy = load_policy()
    devices = policy.get("devices", [])

    if any(d.get("name") == name for d in devices):
        flash(f"Device {name} มีอยู่แล้ว", "error")
        return redirect(url_for("devices.index"))

    devices.append({
        "name": name,
        "vendor": vendor,
        "ip": ip,
        "site": site,
        "status": status
    })
    policy["devices"] = devices
    save_policy(policy)

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

    - safe by default: does NOT `write` unless (a) user checks save, and
      (b) OLT_AUTO_WRITE / OLT_ALLOW_WRITE env enables it.
    - supports preview (dry-run) via button name="dry_run".
    """

    policy = load_policy()
    devices = policy.get("devices", [])
    dev = next((d for d in devices if (d.get("name") or "") == name), None)
    if not dev:
        flash(f"ไม่พบ Device {name}", "error")
        return redirect(url_for("devices.index"))

    ip = (dev.get("ip") or dev.get("address") or "").strip()
    if not ip:
        flash(f"Device {name} ไม่มี IP ใน policy.json", "error")
        return redirect(url_for("devices.index"))

    want_save = (request.form.get("save") or "").strip().lower() in ("1", "true", "yes", "on")
    is_preview = (request.form.get("dry_run") or "").strip().lower() in ("1", "true", "yes", "on")

    # extra safety gate (env)
    allow_write_raw = (_read_env("OLT_ALLOW_WRITE", "") or "").strip().lower()
    if not allow_write_raw:
        allow_write_raw = (_read_env("OLT_AUTO_WRITE", "0") or "0").strip().lower()
    allow_write = allow_write_raw in ("1", "true", "yes", "on")

    save = bool(want_save and allow_write and not is_preview)
    if want_save and not allow_write and not is_preview:
        flash("ปฏิเสธการ write: ต้องเปิด OLT_ALLOW_WRITE=1 (หรือ OLT_AUTO_WRITE=1) ใน secret.env ก่อน", "error")

    try:
        out = bootstrap_device_on_olt(ip, save=save, dry_run=is_preview)
        # flash needs to be reasonably small; keep the end of output (most useful)
        out = (out or "").strip()
        if len(out) > 2500:
            out = "... (truncated)\n" + out[-2400:]

        if is_preview:
            flash(f"Preview Bootstrap (no changes) for {name} ({ip})\n{out}", "info")
        else:
            flash(
                f"Bootstrap AAA on OLT {name} ({ip}) สำเร็จ (write={'ON' if save else 'OFF'})\n{out}",
                "success",
            )
    except Exception as e:
        flash(f"Bootstrap AAA on OLT {name} ({ip}) ล้มเหลว: {e}", "error")

    return redirect(url_for("devices.index"))


@bp.post("/delete/<name>")
def delete_device_form(name):
    policy = load_policy()
    devices = policy.get("devices", [])

    new_devices = [d for d in devices if d.get("name") != name]
    if len(new_devices) == len(devices):
        flash(f"ไม่พบอุปกรณ์ {name}", "error")
        return redirect(url_for("devices.index"))

    policy["devices"] = new_devices
    save_policy(policy)

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

    return render_template(
        "device_edit.html",
        active_page="devices",
        device=target,
    )


@bp.post("/<name>/edit")
def edit_device_submit(name):
    policy = load_policy()
    devices = policy.get("devices", [])

    target = next((d for d in devices if (d.get("name") or "") == name), None)
    if not target:
        flash(f"ไม่พบ Device {name}", "error")
        return redirect(url_for("devices.index"))

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

    # --- อัปเดต field อื่น ๆ ตามเดิมของคุณ (ip/vendor/site/status ฯลฯ) ---
    # target["ip"] = ...
    # save_policy(policy)

    save_policy(policy)
    flash(f"บันทึก Device สำเร็จ", "success")
    return redirect(url_for("devices.index"))



