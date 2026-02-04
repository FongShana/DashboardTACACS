from __future__ import annotations

import time
from collections import Counter

from flask import Blueprint, render_template, request, redirect, url_for

from tacacs_dashboard.services.log_parser import (
    LOG_DIR,
    get_recent_events,
    get_command_events,
)


bp = Blueprint("logs", __name__)


# -----------------------------
# Micro-cache for /logs/auth
# -----------------------------
# Keep it short to preserve "near real-time" behavior while avoiding repeated
# heavy log parsing when multiple users refresh frequently.
_AUTH_CACHE_TTL_SECONDS = 2  # seconds

# Per-process (per gunicorn worker) cache:
# {"ts": float, "mtime": float, "events": list[dict]}
_AUTH_CACHE = {"ts": 0.0, "mtime": 0.0, "events": []}


def _auth_logs_mtime() -> float:
    """Return newest mtime among auth/session log sources.

    We use this to invalidate cache immediately when new TACACS logs arrive.
    """
    if not LOG_DIR.exists():
        return 0.0

    latest = 0.0
    for pat in ("authc-*.log", "authz-*.log", "acct-*.log"):
        for p in LOG_DIR.glob(pat):
            try:
                mt = p.stat().st_mtime
                if mt > latest:
                    latest = mt
            except OSError:
                continue
    return latest


def _get_recent_auth_events_cached(limit: int = 200) -> list[dict]:
    """Cached wrapper for get_recent_events used by /logs/auth."""
    now = time.time()
    cur_mtime = _auth_logs_mtime()

    ts = float(_AUTH_CACHE.get("ts") or 0.0)
    cached_mtime = float(_AUTH_CACHE.get("mtime") or 0.0)
    cached_events = _AUTH_CACHE.get("events") or []

    if cached_events and (now - ts) < _AUTH_CACHE_TTL_SECONDS and cur_mtime <= cached_mtime:
        return cached_events

    events = get_recent_events(limit=limit)
    _AUTH_CACHE["ts"] = now
    _AUTH_CACHE["mtime"] = cur_mtime
    _AUTH_CACHE["events"] = events
    return events


def _get_auth_filters() -> tuple[str, str, str]:
    user_filter = (request.args.get("user") or "").strip()
    device_filter = (request.args.get("device") or "").strip()
    result_filter = (request.args.get("result") or "").strip()
    return user_filter, device_filter, result_filter


def _get_cmd_filters() -> tuple[str, str, str]:
    cmd_user_filter = (request.args.get("cmd_user") or "").strip()
    cmd_device_filter = (request.args.get("cmd_device") or "").strip()
    cmd_contains_filter = (request.args.get("cmd_contains") or "").strip()
    return cmd_user_filter, cmd_device_filter, cmd_contains_filter


@bp.route("/")
def index():
    """Backward-compatible entry point.

    Old UI used a single page and mixed auth + command filters.
    New UI splits into /logs/auth and /logs/command, so this route redirects to
    the best matching subpage while preserving query parameters.
    """
    cmd_user_filter, cmd_device_filter, cmd_contains_filter = _get_cmd_filters()

    # Preserve all query params (even unused ones) for compatibility.
    args = request.args.to_dict(flat=True)

    if cmd_user_filter or cmd_device_filter or cmd_contains_filter:
        return redirect(url_for("logs.command", **args))
    return redirect(url_for("logs.auth", **args))


@bp.route("/auth")
def auth():
    # Filters
    user_filter, device_filter, result_filter = _get_auth_filters()
    cmd_user_filter, cmd_device_filter, cmd_contains_filter = _get_cmd_filters()

    # Parse only auth/session logs for this page
    recent_events = _get_recent_auth_events_cached(limit=200)

    # Dropdown lists
    user_list = sorted({e.get("user") for e in recent_events if e.get("user")})
    device_list = sorted({e.get("device") for e in recent_events if e.get("device")})
    result_list = sorted(
        {
            (e.get("result") or "").upper()
            for e in recent_events
            if e.get("result")
        }
    )

    # Apply filters
    filtered_events: list[dict] = []
    for e in recent_events:
        if user_filter and e.get("user") != user_filter:
            continue
        if device_filter and e.get("device") != device_filter:
            continue
        if result_filter and (e.get("result") or "").upper() != result_filter.upper():
            continue
        filtered_events.append(e)

    # Summary
    total_events = len(filtered_events)
    total_success = sum(
        1
        for e in filtered_events
        if (e.get("result") or "").upper() in ("ACCEPT", "OK", "PASS", "SUCCESS")
    )
    total_fail = sum(
        1
        for e in filtered_events
        if (e.get("result") or "").upper() in ("REJECT", "FAIL", "ERROR")
    )
    unique_user_count = len({e.get("user") for e in filtered_events if e.get("user")})
    unique_device_count = len({e.get("device") for e in filtered_events if e.get("device")})

    return render_template(
        "logs_auth.html",
        active_page="logs",
        active_logs_subpage="auth",
        # data
        recent_events=filtered_events,
        # summary
        total_events=total_events,
        total_success=total_success,
        total_fail=total_fail,
        unique_user_count=unique_user_count,
        unique_device_count=unique_device_count,
        # auth filters
        user_list=user_list,
        device_list=device_list,
        result_list=result_list,
        user_filter=user_filter,
        device_filter=device_filter,
        result_filter=result_filter,
        # command filters (preserve when switching tabs)
        cmd_user_filter=cmd_user_filter,
        cmd_device_filter=cmd_device_filter,
        cmd_contains_filter=cmd_contains_filter,
    )


@bp.route("/command")
def command():
    # Filters (preserve auth filters so the user doesn't lose state)
    user_filter, device_filter, result_filter = _get_auth_filters()
    cmd_user_filter, cmd_device_filter, cmd_contains_filter = _get_cmd_filters()

    # Command audit logs:
    # - default = recent (fast)
    # - if any cmd filter provided -> scan all acct logs (bounded top-N by timestamp)
    scan_all_cmd = bool(cmd_user_filter or cmd_device_filter or cmd_contains_filter)
    command_events = get_command_events(
        limit=1600 if scan_all_cmd else 200,
        scan_all=scan_all_cmd,
        user=cmd_user_filter,
        device=cmd_device_filter,
        contains=cmd_contains_filter,
    )

    # Dropdown lists
    cmd_user_list = sorted({e.get("user") for e in command_events if e.get("user")})
    cmd_device_list = sorted({e.get("device") for e in command_events if e.get("device")})

    # Summary
    total_cmd = len(command_events)
    cmd_unique_user_count = len({e.get("user") for e in command_events if e.get("user")})
    cmd_unique_device_count = len({e.get("device") for e in command_events if e.get("device")})

    cmd_user_breakdown = Counter(
        (e.get("user") or "").strip() for e in command_events if (e.get("user") or "").strip()
    ).most_common(10)

    # User Activity table (from commands) — keep it cheap by not parsing auth logs here
    cmd_user_activity = [
        {"user": u, "count": n}
        for u, n in Counter(
            (e.get("user") or "").strip() for e in command_events if (e.get("user") or "").strip()
        ).most_common()
    ]

    return render_template(
        "logs_command.html",
        active_page="logs",
        active_logs_subpage="command",
        # command data
        command_events=command_events,
        total_cmd=total_cmd,
        cmd_unique_user_count=cmd_unique_user_count,
        cmd_unique_device_count=cmd_unique_device_count,
        cmd_user_breakdown=cmd_user_breakdown,
        cmd_user_activity=cmd_user_activity,
        scan_all_cmd=scan_all_cmd,
        # command filters
        cmd_user_list=cmd_user_list,
        cmd_device_list=cmd_device_list,
        cmd_user_filter=cmd_user_filter,
        cmd_device_filter=cmd_device_filter,
        cmd_contains_filter=cmd_contains_filter,
        # preserve auth filters (hidden inputs + tab switching)
        user_filter=user_filter,
        device_filter=device_filter,
        result_filter=result_filter,
    )


