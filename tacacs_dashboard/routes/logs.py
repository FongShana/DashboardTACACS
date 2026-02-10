from __future__ import annotations

import time
from collections import Counter
from datetime import date, datetime, time as dtime, timedelta
from zoneinfo import ZoneInfo

from flask import Blueprint, render_template, request, redirect, url_for

from tacacs_dashboard.services.log_parser import (
    LOG_DIR,
    get_recent_events,
    get_command_events,
)


bp = Blueprint("logs", __name__)


# -----------------------------
# Micro-caches for /logs/*
# -----------------------------
# These caches are intentionally short to preserve "near real-time" refresh while
# reducing repeated heavy log parsing when multiple users refresh frequently.
#
# NOTE: caches are per gunicorn worker process (normal for gunicorn).

_AUTH_CACHE_TTL_SECONDS = 2  # seconds
_CMD_CACHE_TTL_SECONDS = 2   # seconds

# Cache shapes:
# {"ts": float, "mtime": float, "events": list[dict]}
_AUTH_CACHE = {"ts": 0.0, "mtime": 0.0, "events": []}
_CMD_CACHE = {"ts": 0.0, "mtime": 0.0, "events": []}


def _latest_mtime(patterns: tuple[str, ...]) -> float:
    if not LOG_DIR.exists():
        return 0.0

    latest = 0.0
    for pat in patterns:
        for p in LOG_DIR.glob(pat):
            try:
                mt = p.stat().st_mtime
                if mt > latest:
                    latest = mt
            except OSError:
                continue
    return latest


def _get_recent_auth_events_cached(limit: int = 400) -> list[dict]:
    """Cached wrapper for get_recent_events used by /logs/auth."""
    now = time.time()
    cur_mtime = _latest_mtime(("authc-*.log", "authz-*.log", "acct-*.log"))

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


def _get_recent_cmd_events_cached(limit: int = 400) -> list[dict]:
    """Cached wrapper for get_command_events used by /logs/command (fast mode only)."""
    now = time.time()
    cur_mtime = _latest_mtime(("acct-*.log",))

    ts = float(_CMD_CACHE.get("ts") or 0.0)
    cached_mtime = float(_CMD_CACHE.get("mtime") or 0.0)
    cached_events = _CMD_CACHE.get("events") or []

    if cached_events and (now - ts) < _CMD_CACHE_TTL_SECONDS and cur_mtime <= cached_mtime:
        return cached_events

    events = get_command_events(limit=limit, scan_all=False, user="", device="", contains="")
    _CMD_CACHE["ts"] = now
    _CMD_CACHE["mtime"] = cur_mtime
    _CMD_CACHE["events"] = events
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


_DISPLAY_TZ = ZoneInfo("Asia/Bangkok")

def _parse_ymd(s: str) -> date | None:
    s = (s or "").strip()
    if not s:
        return None
    try:
        return date.fromisoformat(s)
    except Exception:
        return None


def _get_date_filters() -> tuple[str, str, datetime | None, datetime | None]:
    """Parse YYYY-MM-DD date filters from query string.

    Returns:
      (date_from_str, date_to_str, start_dt_local, end_dt_local_exclusive)

    Behavior:
      - if only one side is set, treat it as a single-day filter
      - swap if user gives reversed range
    """
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()

    d_from = _parse_ymd(date_from)
    d_to = _parse_ymd(date_to)

    if d_from and not d_to:
        d_to = d_from
        date_to = date_from
    if d_to and not d_from:
        d_from = d_to
        date_from = date_to

    if d_from and d_to and d_to < d_from:
        d_from, d_to = d_to, d_from
        date_from, date_to = date_to, date_from

    if not d_from or not d_to:
        return date_from, date_to, None, None

    start = datetime.combine(d_from, dtime(0, 0)).replace(tzinfo=_DISPLAY_TZ)
    end = datetime.combine(d_to + timedelta(days=1), dtime(0, 0)).replace(tzinfo=_DISPLAY_TZ)
    return date_from, date_to, start, end



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
    date_from, date_to, start_dt, end_dt = _get_date_filters()

    # Parse only auth/session logs for this page.
    # IMPORTANT: when a date range is wide, the total events can be huge.
    # If we LIMIT first then apply user/device filters in Python, results can look
    # "missing" (older matches pushed out by newer unrelated events). To keep
    # filtering correct, we fetch:
    #   (1) a sample (unfiltered) for dropdown lists
    #   (2) a filtered query (push filters down) for the table/summary
    if start_dt and end_dt:
        # Unfiltered sample for dropdown lists
        dropdown_events = get_recent_events(limit=8000, start_dt=start_dt, end_dt=end_dt)

        # Filtered query for the table/summary (push down filters before LIMIT)
        if user_filter or device_filter or result_filter:
            filtered_events = get_recent_events(
                limit=8000,
                start_dt=start_dt,
                end_dt=end_dt,
                user=user_filter,
                device=device_filter,
                result=result_filter,
            )
        else:
            filtered_events = dropdown_events

        events_for_lists = dropdown_events
    else:
        # No date filter: keep fast + cached behavior, then filter in Python
        events_for_lists = _get_recent_auth_events_cached(limit=400)

        filtered_events: list[dict] = []
        for e in events_for_lists:
            if user_filter and e.get("user") != user_filter:
                continue
            if device_filter and e.get("device") != device_filter:
                continue
            if result_filter and (e.get("result") or "").upper() != result_filter.upper():
                continue
            filtered_events.append(e)

    # Dropdown lists
    user_list = sorted({e.get("user") for e in events_for_lists if e.get("user")})
    device_list = sorted({e.get("device") for e in events_for_lists if e.get("device")})
    result_list = sorted(
        {
            (e.get("result") or "").upper()
            for e in events_for_lists
            if e.get("result")
        }
    )

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
        # date filters
        date_from=date_from,
        date_to=date_to,
    )


@bp.route("/command")
def command():
    # Filters (preserve auth filters so the user doesn't lose state)
    user_filter, device_filter, result_filter = _get_auth_filters()
    cmd_user_filter, cmd_device_filter, cmd_contains_filter = _get_cmd_filters()
    date_from, date_to, start_dt, end_dt = _get_date_filters()

    # Command audit logs:
    # - default = recent (fast)
    # - if any cmd filter OR date filter provided -> scan historical (or use SQLite index)
    scan_all_cmd = bool(cmd_user_filter or cmd_device_filter or cmd_contains_filter or (start_dt and end_dt))
    if scan_all_cmd:
        command_events = get_command_events(
            limit=8000,
            scan_all=True,
            user=cmd_user_filter,
            device=cmd_device_filter,
            contains=cmd_contains_filter,
            start_dt=start_dt,
            end_dt=end_dt,
        )
    else:
        # Fast mode: micro-cache (mtime-aware) to reduce repeated parsing on refresh storms
        command_events = _get_recent_cmd_events_cached(limit=400)

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
        # date filters
        date_from=date_from,
        date_to=date_to,
    )


