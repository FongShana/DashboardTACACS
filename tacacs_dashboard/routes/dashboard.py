# tacacs_dashboard/routes/dashboard.py
from __future__ import annotations

from flask import Blueprint, render_template

from tacacs_dashboard.services.log_parser import get_recent_events, get_summary
from tacacs_dashboard.services.policy_store import load_policy

bp = Blueprint("dashboard", __name__)

def _build_user_role_map() -> dict[str, str]:
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
    summary = get_summary()
    events = get_recent_events(limit=50)

    # ✅ เติม role ให้แต่ละ event จาก policy.json
    role_map = _build_user_role_map()
    for e in events:
        user = (e.get("user") or "").strip()
        e["role"] = role_map.get(user, "-")  # user ที่ไม่อยู่ใน policy (เช่น zte) จะเป็น "-"

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        summary=summary,
        events=events,
    )

