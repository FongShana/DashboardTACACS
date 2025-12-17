from flask import Blueprint, render_template, request, redirect, url_for, flash
from tacacs_dashboard.services.policy_store import load_policy, save_policy

bp = Blueprint("devices", __name__)


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

    target = None
    for d in devices:
        if d.get("name") == name:
            target = d
            break

    if not target:
        flash(f"ไม่พบ Device {name}", "error")
        return redirect(url_for("devices.index"))

    # อัปเดต field ที่แก้ได้
    target["vendor"] = request.form.get("vendor", "").strip()
    target["ip"]     = request.form.get("ip", "").strip()
    target["site"]   = request.form.get("site", "").strip()
    target["status"] = request.form.get("status", "").strip()

    save_policy(policy)
    flash(f"อัปเดต Device {name} เรียบร้อยแล้ว", "success")
    return redirect(url_for("devices.index"))
