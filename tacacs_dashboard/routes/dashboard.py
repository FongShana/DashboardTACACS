# tacacs_dashboard/routes/dashboard.py
from __future__ import annotations

import time
import threading
from flask import Blueprint, render_template

from tacacs_dashboard.services.log_parser import get_recent_events
from tacacs_dashboard.services.policy_store import load_policy

bp = Blueprint("dashboard", __name__)

# Cache dashboard summary/events for a short time to reduce log parsing pressure.
# Note: this cache is per-Gunicorn-worker (in-memory). That is OK for a small TTL.
_DASHBOARD_CACHE_TTL_SECONDS = 10
_dashboard_cache_lock = threading.Lock()
_dashboard_compute_lock = threading.Lock()
_dashboard_cache: dict[str, object] = {
    "ts": 0.0,
    "payload": None,  # tuple[dict, list]
}


def _build_user_role_map(policy: dict) -> dict[str, str]:
    """Map username -> role from policy.json."""
    m: dict[str, str] = {}
    for u in (policy.get("users") or []):
        if not isinstance(u, dict):
            continue
        name = (u.get("username") or "").strip()
        role = (u.get("roles") or u.get("role") or "-")
        role = (role or "-").strip()
        if name:
            m[name] = role
    return m


def _compute_dashboard_payload() -> tuple[dict, list]:
    # Read more events to compute summary, then slice for display.
    all_events = get_recent_events(limit=2000)

    # Load policy once (used for role map + total users)
    policy = load_policy()

    # Fill role per event from policy
    role_map = _build_user_role_map(policy)
    for e in all_events:
        user = (e.get("user") or "").strip()
        e["role"] = role_map.get(user, "-")

    # 1) All TACACS+ Users = total users in policy.json
    policy_users = [
        u
        for u in (policy.get("users") or [])
        if isinstance(u, dict) and (u.get("username") or "").strip()
    ]
    all_users_count = len(policy_users)

    # 2) Failed Login Attempts = count login rejects
    failed_logins_count = sum(
        1
        for e in all_events
        if (e.get("action") == "login" and (e.get("result") or "").upper() == "REJECT")
    )

    # 3) Registered OLT Devices = unique device seen in logs
    devices = {
        (e.get("device") or "").strip()
        for e in all_events
        if (e.get("device") or "").strip()
    }
    devices_count = len(devices)

    # 4) Roles / Privilege Profiles = unique role seen after filling roles
    roles = {
        (e.get("role") or "-").strip()
        for e in all_events
        if (e.get("role") or "-").strip() not in ("", "-")
    }
    roles_count = len(roles)

    summary = {
        "all_users": all_users_count,
        "failed_logins": failed_logins_count,
        "devices": devices_count,
        "roles": roles_count,
    }

    # Recent Security Events table (latest 50)
    events = all_events[:50]

    return summary, events


def _get_dashboard_payload_cached() -> tuple[dict, list]:
    now = time.time()

    # Fast path: return cached payload if still valid.
    with _dashboard_cache_lock:
        ts = float(_dashboard_cache.get("ts") or 0.0)
        payload = _dashboard_cache.get("payload")
        if payload is not None and (now - ts) < _DASHBOARD_CACHE_TTL_SECONDS:
            return payload  # type: ignore[return-value]

    # Slow path: compute with a compute mutex (avoid stampede)
    with _dashboard_compute_lock:
        now = time.time()
        with _dashboard_cache_lock:
            ts = float(_dashboard_cache.get("ts") or 0.0)
            payload = _dashboard_cache.get("payload")
            if payload is not None and (now - ts) < _DASHBOARD_CACHE_TTL_SECONDS:
                return payload  # type: ignore[return-value]

        summary, events = _compute_dashboard_payload()

        with _dashboard_cache_lock:
            _dashboard_cache["ts"] = now
            _dashboard_cache["payload"] = (summary, events)

        return summary, events


@bp.route("/")
def index():
    summary, events = _get_dashboard_payload_cached()

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        summary=summary,
        events=events,
    )
