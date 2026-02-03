from __future__ import annotations

from flask import Blueprint, jsonify, request, session
from tacacs_dashboard.services.log_parser import get_recent_events, get_summary, get_all_events
from tacacs_dashboard.services.policy_store import load_policy, update_policy
from tacacs_dashboard.services.tacacs_config import build_config_text
from tacacs_dashboard.services.access_control import allowed_device_group_ids, device_in_scope

bp = Blueprint("api", __name__)


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400, **extra):
        super().__init__(message)
        self.message = message
        self.status = int(status or 400)
        self.extra = extra or {}


def _err(message: str, status: int = 400, **extra):
    raise ApiError(message, status=status, **extra)


@bp.get("/summary")
def api_summary():
    """Give back summarize data as Dashboard as JSON
    Ex. active_users, failed_logins, devices, roles
    """
    summary = get_summary()
    return jsonify(summary)


@bp.get("/logs")
def api_logs():
    """Give back log as JSON. Support query string ?limit=20"""
    limit = request.args.get("limit", default=50, type=int)
    events = get_recent_events(limit=limit)
    return jsonify(events)


@bp.get("/logs/all")
def api_logs_all():
    """See all log (from sample file right now). Be careful that real log maybe too big"""
    events = get_all_events()
    return jsonify(events)


@bp.get("/policy")
def api_policy_all():
    policy = load_policy()
    role = (session.get("web_role") or "admin").strip().lower()
    uname = (session.get("web_username") or "").strip()
    allowed_gids = allowed_device_group_ids(role, uname)
    if allowed_gids is not None:
        # admin: only expose in-scope devices and their groups
        devices = policy.get("devices", []) or []
        policy["devices"] = [d for d in devices if isinstance(d, dict) and device_in_scope(d, allowed_gids)]
        groups = policy.get("device_groups", []) or []
        allowed_set = set(allowed_gids)
        policy["device_groups"] = [g for g in groups if isinstance(g, dict) and (g.get("id") or "") in allowed_set]
    return jsonify(policy)


@bp.get("/users")
def api_users():
    return jsonify(load_policy().get("users", []))


@bp.get("/roles")
def api_roles():
    return jsonify(load_policy().get("roles", []))


@bp.get("/devices")
def api_devices():
    policy = load_policy()
    devices = policy.get("devices", []) or []
    role = (session.get("web_role") or "admin").strip().lower()
    uname = (session.get("web_username") or "").strip()
    allowed_gids = allowed_device_group_ids(role, uname)
    if allowed_gids is not None:
        devices = [d for d in devices if isinstance(d, dict) and device_in_scope(d, allowed_gids)]
    return jsonify(devices)


@bp.get("/tacacs/config/preview")
def api_tacacs_config_preview():
    text = build_config_text()
    return jsonify({"config": text})


# -----------------------
# Policy: Users (CRUD basic)  -- locked via update_policy()
# -----------------------

@bp.post("/users")
def api_create_user():
    """เพิ่ม user ใหม่ลงใน policy.json
    body ต้องเป็น JSON เช่น:
    {
      "username": "eng_bkk2",
      "role": "OLT_ENGINEER",
      "status": "Active"
    }
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    role = (data.get("role") or data.get("roles") or "").strip()
    status = (data.get("status") or "Active").strip() or "Active"

    if not username or not role:
        return jsonify({"error": "username and role are required"}), 400

    try:
        def _mut(policy: dict):
            users = policy.get("users", []) or []
            roles = policy.get("roles", []) or []

            # ตรวจว่า role นี้มีอยู่ในระบบจริงไหม (เช็คกับ roles list)
            role_names = { (r.get("name") or "").strip() for r in roles if isinstance(r, dict) }
            if role not in role_names:
                _err(
                    f"role '{role}' does not exist",
                    status=400,
                    available_roles=sorted([r for r in role_names if r]),
                )

            # กัน username ซ้ำ
            if any(isinstance(u, dict) and (u.get("username") or "").strip() == username for u in users):
                _err(f"user '{username}' already exists", status=409)

            # สร้าง user object ใหม่
            user = {
                "username": username,
                "roles": role,          # ใช้ field 'roles' ให้ตรงกับ template เดิม
                "status": status,
                "last_login": "-"       # ค่าเริ่มต้น
            }
            users.append(user)
            policy["users"] = users
            return user

        user = update_policy(_mut)
        return jsonify(user), 201

    except ApiError as e:
        payload = {"error": e.message}
        payload.update(e.extra or {})
        return jsonify(payload), e.status
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.delete("/users/<username>")
def api_delete_user(username):
    """ลบ user ตาม username จาก policy.json"""
    username = (username or "").strip()
    if not username:
        return jsonify({"error": "username is required"}), 400

    try:
        def _mut(policy: dict):
            users = policy.get("users", []) or []
            new_users = [u for u in users if not (isinstance(u, dict) and (u.get("username") or "").strip() == username)]
            if len(new_users) == len(users):
                _err(f"user '{username}' not found", status=404)
            policy["users"] = new_users
            return {"message": f"user '{username}' deleted"}

        out = update_policy(_mut)
        return jsonify(out)

    except ApiError as e:
        payload = {"error": e.message}
        payload.update(e.extra or {})
        return jsonify(payload), e.status
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------
# Policy: Devices (CRUD basic) -- locked via update_policy()
# -----------------------

def _is_valid_ipv4(ip: str) -> bool:
    """เช็คว่าเป็น IPv4 รูปแบบง่าย ๆ"""
    parts = (ip or "").split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    return all(0 <= n <= 255 for n in nums)


@bp.post("/devices")
def api_create_device():
    """เพิ่ม device ใหม่ลงใน policy.json

    ตัวอย่าง JSON:
    {
      "name": "OLT_ZTE_BTG3",
      "vendor": "ZTE",
      "ip": "10.235.110.30",
      "site": "SITE-C",
      "status": "Online",
      "group_id": "bkk"
    }
    """
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    vendor = (data.get("vendor") or "Unknown").strip() or "Unknown"
    ip = (data.get("ip") or "").strip()
    site = (data.get("site") or "-").strip() or "-"
    status = (data.get("status") or "Unknown").strip() or "Unknown"
    group_id = (data.get("group_id") or "").strip().lower()

    if not name or not ip:
        return jsonify({"error": "name และ ip เป็นฟิลด์จำเป็น"}), 400

    if not _is_valid_ipv4(ip):
        return jsonify({"error": f"IP '{ip}' ไม่ใช่ IPv4 ที่ถูกต้อง"}), 400

    # enforce group scope for admin
    role = (session.get("web_role") or "admin").strip().lower()
    uname = (session.get("web_username") or "").strip()
    allowed_gids = allowed_device_group_ids(role, uname)
    if allowed_gids is not None:
        if not allowed_gids:
            return jsonify({"error": "this admin has no device groups assigned"}), 403
        if not group_id:
            return jsonify({"error": "group_id is required for admin"}), 400
        if group_id not in set(allowed_gids):
            return jsonify({"error": "permission denied for this group"}), 403

    try:
        def _mut(policy: dict):
            devices = policy.get("devices", []) or []

            # group existence check inside the same lock to avoid race
            if group_id:
                groups = policy.get("device_groups", []) or []
                allowed_group_ids = { (g.get("id") or "").strip() for g in groups if isinstance(g, dict) }
                if group_id not in allowed_group_ids:
                    _err("group_id not found", status=400)

            # กันชื่อ device ซ้ำ
            if any(isinstance(d, dict) and (d.get("name") or "").strip() == name for d in devices):
                _err(f"device '{name}' มีอยู่แล้ว", status=409)

            device = {
                "name": name,
                "vendor": vendor,
                "ip": ip,
                "site": site,
                "status": status,
                "group_id": group_id,
            }

            devices.append(device)
            policy["devices"] = devices
            return device

        device = update_policy(_mut)
        return jsonify(device), 201

    except ApiError as e:
        payload = {"error": e.message}
        payload.update(e.extra or {})
        return jsonify(payload), e.status
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.delete("/devices/<name>")
def api_delete_device(name):
    """ลบ device ตาม name จาก policy.json"""
    name = (name or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    role = (session.get("web_role") or "admin").strip().lower()
    uname = (session.get("web_username") or "").strip()
    allowed_gids = allowed_device_group_ids(role, uname)

    try:
        def _mut(policy: dict):
            devices = policy.get("devices", []) or []

            # scope check (admin)
            if allowed_gids is not None:
                target = next((d for d in devices if isinstance(d, dict) and (d.get("name") or "").strip() == name), None)
                if not target or not device_in_scope(target, allowed_gids):
                    _err("permission denied", status=403)

            new_devices = [d for d in devices if not (isinstance(d, dict) and (d.get("name") or "").strip() == name)]
            if len(new_devices) == len(devices):
                _err(f"device '{name}' ไม่พบในระบบ", status=404)

            policy["devices"] = new_devices
            return {"message": f"device '{name}' ถูกลบแล้ว"}

        out = update_policy(_mut)
        return jsonify(out)

    except ApiError as e:
        payload = {"error": e.message}
        payload.update(e.extra or {})
        return jsonify(payload), e.status
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------
# Policy: Roles (CRUD basic) -- locked via update_policy()
# -----------------------

@bp.post("/roles")
def api_create_role():
    """เพิ่ม role ใหม่ลงใน policy.json

    ตัวอย่าง JSON:
    {
      "name": "OLT_READONLY",
      "description": "สิทธิ์ดูอย่างเดียว",
      "privilege": "1 / read-only"
    }
    """
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    description = (data.get("description") or "").strip()
    privilege = (data.get("privilege") or "").strip()

    if not name:
        return jsonify({"error": "name เป็นฟิลด์จำเป็น"}), 400

    try:
        def _mut(policy: dict):
            roles = policy.get("roles", []) or []

            if any(isinstance(r, dict) and (r.get("name") or "").strip() == name for r in roles):
                _err(f"role '{name}' มีอยู่แล้ว", status=409)

            role = {
                "name": name,
                "description": description,
                "privilege": privilege,
                "members": 0
            }
            roles.append(role)
            policy["roles"] = roles
            return role

        role_obj = update_policy(_mut)
        return jsonify(role_obj), 201

    except ApiError as e:
        payload = {"error": e.message}
        payload.update(e.extra or {})
        return jsonify(payload), e.status
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.delete("/roles/<name>")
def api_delete_role(name):
    """ลบ role ตาม name จาก policy.json
    ถ้ามี user ใช้ role นี้อยู่ จะไม่ให้ลบ
    """
    name = (name or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    try:
        def _mut(policy: dict):
            roles = policy.get("roles", []) or []
            users = policy.get("users", []) or []

            used_by = [
                (u.get("username") or "")
                for u in users
                if isinstance(u, dict) and ((u.get("roles") == name) or (u.get("role") == name))
            ]
            used_by = [u for u in used_by if u]
            if used_by:
                _err(
                    f"role '{name}' ยังถูกใช้งานโดย users: {', '.join(used_by)}",
                    status=400,
                    hint="เปลี่ยน role ของ users เหล่านี้ก่อน แล้วค่อยลบ role",
                )

            new_roles = [r for r in roles if not (isinstance(r, dict) and (r.get("name") or "").strip() == name)]
            if len(new_roles) == len(roles):
                _err(f"role '{name}' ไม่พบในระบบ", status=404)

            policy["roles"] = new_roles
            return {"message": f"role '{name}' ถูกลบแล้ว"}

        out = update_policy(_mut)
        return jsonify(out)

    except ApiError as e:
        payload = {"error": e.message}
        payload.update(e.extra or {})
        return jsonify(payload), e.status
    except Exception as e:
        return jsonify({"error": str(e)}), 500
