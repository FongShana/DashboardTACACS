# tacacs_dashboard/routes/dashboard.py
from __future__ import annotations

from flask import Blueprint, render_template

from tacacs_dashboard.services.log_parser import get_recent_events
from tacacs_dashboard.services.policy_store import load_policy

bp = Blueprint("dashboard", __name__)


def _build_user_role_map() -> dict[str, str]:
    """
    map username -> role จาก policy.json
    """
    policy = load_policy()
    m: dict[str, str] = {}
    for u in (policy.get("users") or []):
        name = (u.get("username") or "").strip()
        role = (u.get("roles") or u.get("role") or "-")
        role = (role or "-").strip()
        if name:
            m[name] = role
    return m


@bp.route("/")
def index():
    # อ่าน event เยอะหน่อยเพื่อคำนวณ summary (แล้วค่อยตัดไปโชว์ตาราง)
    all_events = get_recent_events(limit=2000)

    # เติม role ให้แต่ละ event จาก policy.json
    role_map = _build_user_role_map()
    for e in all_events:
        user = (e.get("user") or "").strip()
        e["role"] = role_map.get(user, "-")

    # -----------------------
    # ✅ สร้าง summary ให้ตรงกับ dashboard.html
    # -----------------------
    # 1) Recent TACACS+ Users = จำนวน user ที่ login สำเร็จ (นับ unique)
    recent_login_users = {
        (e.get("user") or "").strip()
        for e in all_events
        if (e.get("action") == "login" and (e.get("result") or "").upper() == "ACCEPT")
    }
    # ถ้าจะไม่เอา local/admin เช่น zte ออก ให้ uncomment บรรทัดนี้
    # recent_login_users.discard("zte")
    recent_login_users.discard("")

    recent_users_count = len(recent_login_users)

    # 2) Failed Login Attempts = จำนวน login ที่ reject
    failed_logins_count = sum(
        1
        for e in all_events
        if (e.get("action") == "login" and (e.get("result") or "").upper() == "REJECT")
    )

    # 3) Registered OLT Devices = unique device ที่พบใน log
    devices = {
        (e.get("device") or "").strip()
        for e in all_events
        if (e.get("device") or "").strip()
    }
    devices_count = len(devices)

    # 4) Roles / Privilege Profiles = unique role ที่พบจาก user ใน events (หลังเติม role แล้ว)
    roles = {
        (e.get("role") or "-").strip()
        for e in all_events
        if (e.get("role") or "-").strip() not in ("", "-")
    }
    roles_count = len(roles)

    summary = {
        "recent_users": recent_users_count,
        "failed_logins": failed_logins_count,
        "devices": devices_count,
        "roles": roles_count,
    }

    # ตาราง Recent Security Events (เอาแค่ล่าสุด 50)
    events = all_events[:50]

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        summary=summary,
        events=events,
    )

