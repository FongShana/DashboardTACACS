import re
from flask import Blueprint, render_template, request, redirect, url_for, flash

from tacacs_dashboard.services.policy_store import load_policy, save_policy
from tacacs_dashboard.services.tacacs_config import _read_env
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
    bootstrap = (request.form.get("bootstrap") or "").strip().lower() in ("1", "true", "yes", "on")

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

    # Optional: bootstrap AAA templates + system-user binds on the OLT
    if bootstrap:
        auto_write = (_read_env("OLT_AUTO_WRITE", "0") or "0").strip().lower()
        save = auto_write in ("1", "true", "yes")
        try:
            out = bootstrap_device_on_olt(ip, save=save, dry_run=False)
            msg = out if len(out) <= 400 else out[:400] + " ... (truncated)"
            flash(
                f"Bootstrap AAA บน OLT {ip} สำเร็จ (save={'ON' if save else 'OFF'}): {msg}",
                "success",
            )
        except Exception as e:
            flash(f"Bootstrap AAA บน OLT {ip} ล้มเหลว: {e}", "error")

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


