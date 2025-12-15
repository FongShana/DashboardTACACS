from flask import Blueprint, jsonify, request, Response
from tacacs_dashboard.services.log_parser import get_recent_events, get_summary, get_all_events
from tacacs_dashboard.services.policy_store import load_policy, save_policy
from tacacs_dashboard.services.tacacs_config import build_config_text

bp = Blueprint("api", __name__)

@bp.get("/summary")
def api_summary():
    """
    Give back summarize data as Dashboard as JSON
    Ex. active_users, failed_logins, devices, roles
    """
    summary = get_summary()
    return jsonify(summary)


@bp.get("/logs")
def api_logs():
    """
    Give back log as JSON
    Support query string ?limit=20
    """
    limit = request.args.get("limit", default=50, type=int)
    events = get_recent_events(limit=limit)
    return jsonify(events)


@bp.get("/logs/all")
def api_logs_all():
    """
    See all log (from sample file right now)
    Be careful that real log maybe too big
    """
    events = get_all_events()
    return jsonify(events)

@bp.get("/policy")
def api_policy_all():
    return jsonify(load_policy())

@bp.get("/users")
def api_users():
    return jsonify(load_policy().get("users", []))

@bp.get("/roles")
def api_roles():
    return jsonify(load_policy().get("roles", []))

@bp.get("/devices")
def api_devices():
    return jsonify(load_policy().get("devices", []))

@bp.get("/tacacs/config/preview")
def api_tacacs_config_preview():
    text = build_config_text()
    return jsonify({"config": text})

# -----------------------
# Policy: Users (CRUD basic)
# -----------------------

@bp.post("/users")
def api_create_user():
    """
    เพิ่ม user ใหม่ลงใน policy.json
    body ต้องเป็น JSON เช่น:
    {
      "username": "eng_bkk2",
      "role": "OLT_ENGINEER",
      "status": "Active"
    }
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    role = data.get("role") or data.get("roles")
    status = data.get("status", "Active")

    if not username or not role:
        return jsonify({
            "error": "username and role are required"
        }), 400

    policy = load_policy()
    users = policy.get("users", [])
    roles = policy.get("roles", [])

    # ตรวจว่า role นี้มีอยู่ในระบบจริงไหม (เช็คกับ roles list)
    role_names = {r.get("name") for r in roles}
    if role not in role_names:
        return jsonify({
            "error": f"role '{role}' does not exist",
            "available_roles": sorted(list(role_names))
        }), 400

    # กัน username ซ้ำ
    if any(u.get("username") == username for u in users):
        return jsonify({
            "error": f"user '{username}' already exists"
        }), 409  # Conflict

    # สร้าง user object ใหม่
    user = {
        "username": username,
        "roles": role,          # ใช้ field 'roles' ให้ตรงกับ template เดิม
        "status": status,
        "last_login": "-"       # ค่าเริ่มต้น
    }

    users.append(user)
    policy["users"] = users
    save_policy(policy)

    return jsonify(user), 201


@bp.delete("/users/<username>")
def api_delete_user(username):
    """
    ลบ user ตาม username จาก policy.json
    """
    policy = load_policy()
    users = policy.get("users", [])

    new_users = [u for u in users if u.get("username") != username]

    if len(new_users) == len(users):
        return jsonify({
            "error": f"user '{username}' not found"
        }), 404

    policy["users"] = new_users
    save_policy(policy)

    return jsonify({"message": f"user '{username}' deleted"})

# -----------------------
# Policy: Devices (CRUD basic)
# -----------------------

def _is_valid_ipv4(ip: str) -> bool:
    """เช็คว่าเป็น IPv4 รูปแบบง่าย ๆ"""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    return all(0 <= n <= 255 for n in nums)


@bp.post("/devices")
def api_create_device():
    """
    เพิ่ม device ใหม่ลงใน policy.json

    ตัวอย่าง JSON:
    {
      "name": "OLT_ZTE_BTG3",
      "vendor": "ZTE",
      "ip": "10.235.110.30",
      "site": "SITE-C",
      "status": "Online"
    }
    """
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    vendor = data.get("vendor", "Unknown")
    ip = data.get("ip")
    site = data.get("site", "-")
    status = data.get("status", "Unknown")

    if not name or not ip:
        return jsonify({
            "error": "name และ ip เป็นฟิลด์จำเป็น"
        }), 400

    if not _is_valid_ipv4(ip):
        return jsonify({
            "error": f"IP '{ip}' ไม่ใช่ IPv4 ที่ถูกต้อง"
        }), 400

    policy = load_policy()
    devices = policy.get("devices", [])

    # กันชื่อ device ซ้ำ
    if any(d.get("name") == name for d in devices):
        return jsonify({
            "error": f"device '{name}' มีอยู่แล้ว"
        }), 409  # Conflict

    device = {
        "name": name,
        "vendor": vendor,
        "ip": ip,
        "site": site,
        "status": status
    }

    devices.append(device)
    policy["devices"] = devices
    save_policy(policy)

    return jsonify(device), 201

@bp.delete("/devices/<name>")
def api_delete_device(name):
    """
    ลบ device ตาม name จาก policy.json
    """
    policy = load_policy()
    devices = policy.get("devices", [])

    new_devices = [d for d in devices if d.get("name") != name]

    if len(new_devices) == len(devices):
        return jsonify({
            "error": f"device '{name}' ไม่พบในระบบ"
        }), 404

    policy["devices"] = new_devices
    save_policy(policy)

    return jsonify({"message": f"device '{name}' ถูกลบแล้ว"})

