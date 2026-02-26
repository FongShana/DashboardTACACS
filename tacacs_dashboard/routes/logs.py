from __future__ import annotations

import os
import sqlite3
import time
from collections import Counter
from datetime import date, datetime, time as dtime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
from urllib.parse import urlencode

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify

from tacacs_dashboard.services.log_parser import (
    LOG_DIR,
    get_recent_events,
    get_command_events,
)

from tacacs_dashboard.services import policy_store
from tacacs_dashboard.services.access_control import allowed_device_group_ids, device_in_scope

# Optional SQLite indexer (distinct result choices)
try:
    from tacacs_dashboard.services import log_sqlite
except Exception:  # pragma: no cover
    log_sqlite = None



bp = Blueprint("logs", __name__)


# -----------------------------
# Config helpers (secret.env)
# -----------------------------
_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_SECRET_ENV_PATH = _BASE_DIR / "secret.env"


def _read_env(key: str, default: str = "") -> str:
    v = os.getenv(key)
    if v is not None and str(v).strip() != "":
        return str(v).strip()

    if not _SECRET_ENV_PATH.exists():
        return default

    try:
        for line in _SECRET_ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
    except Exception:
        return default

    return default


def _env_bool(key: str, default: bool = False) -> bool:
    v = (_read_env(key, "1" if default else "0") or "").strip().lower()
    return v in ("1", "true", "yes", "y", "on")


def _parse_bool(v: str | None, default: bool = False) -> bool:
    if v is None:
        return bool(default)
    s = (v or "").strip().lower()
    if s == "":
        return bool(default)
    return s in ("1", "true", "yes", "y", "on")


_NOISE_USERS_CACHE: dict = {"ts": 0.0, "mtime": 0.0, "users": set(), "default_hide": False}


def _get_noise_users() -> tuple[set[str], bool]:
    """Return (noise_users_lower_set, default_hide_noise_flag)."""
    now = time.time()
    mtime = 0.0
    try:
        if _SECRET_ENV_PATH.exists():
            mtime = _SECRET_ENV_PATH.stat().st_mtime
    except Exception:
        mtime = 0.0

    cached_ts = float(_NOISE_USERS_CACHE.get("ts") or 0.0)
    cached_mtime = float(_NOISE_USERS_CACHE.get("mtime") or 0.0)
    if (now - cached_ts) < 2.0 and mtime == cached_mtime:
        return set(_NOISE_USERS_CACHE.get("users") or set()), bool(_NOISE_USERS_CACHE.get("default_hide") or False)

    raw = (_read_env("LOGS_HIDE_USERS", "zte") or "zte").strip()
    users = set()
    for part in raw.split(","):
        u = (part or "").strip().lower()
        if u:
            users.add(u)

    default_hide = _env_bool("LOGS_HIDE_NOISE_DEFAULT", default=False)

    _NOISE_USERS_CACHE["ts"] = now
    _NOISE_USERS_CACHE["mtime"] = mtime
    _NOISE_USERS_CACHE["users"] = users
    _NOISE_USERS_CACHE["default_hide"] = default_hide
    return users, default_hide


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


def _get_recent_auth_events_cached(limit: int = 400, *, max_files: int = 4, max_lines_each: int = 6000) -> list[dict]:
    """Cached wrapper for get_recent_events used by /logs/auth.

    Cache is keyed by (limit, max_files, max_lines_each) to avoid returning a too-small sample.
    """
    now = time.time()
    cur_mtime = _latest_mtime(("authc-*.log", "authz-*.log", "acct-*.log"))

    ts = float(_AUTH_CACHE.get("ts") or 0.0)
    cached_mtime = float(_AUTH_CACHE.get("mtime") or 0.0)
    cached_events = _AUTH_CACHE.get("events") or []

    cached_limit = int(_AUTH_CACHE.get("limit") or 0)
    cached_max_files = int(_AUTH_CACHE.get("max_files") or 0)
    cached_max_lines = int(_AUTH_CACHE.get("max_lines_each") or 0)

    same_cfg = (
        cached_limit == int(limit)
        and cached_max_files == int(max_files)
        and cached_max_lines == int(max_lines_each)
    )

    if (
        cached_events
        and same_cfg
        and (now - ts) < _AUTH_CACHE_TTL_SECONDS
        and cur_mtime <= cached_mtime
    ):
        return cached_events

    events = get_recent_events(limit=limit, max_files=int(max_files), max_lines_each=int(max_lines_each))
    _AUTH_CACHE["ts"] = now
    _AUTH_CACHE["mtime"] = cur_mtime
    _AUTH_CACHE["events"] = events
    _AUTH_CACHE["limit"] = int(limit)
    _AUTH_CACHE["max_files"] = int(max_files)
    _AUTH_CACHE["max_lines_each"] = int(max_lines_each)
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

def _get_group_filter() -> str:
    return (request.args.get('group') or '').strip().lower()


def _scope_device_ips_for_admin(*, group_to_ips: dict) -> set[str] | None:
    """Return device IPs the current web user is allowed to see.

    - superadmin -> None (no restriction)
    - admin -> union of device IPs in allowed device groups

    Note: group_to_ips passed in is already restricted by admin scope (see
    _get_device_groups_and_ips), so we can safely union its values.
    """
    allowed = _allowed_group_ids_from_session()
    if allowed is None:
        return None

    ips: set[str] = set()
    try:
        for _gid, arr in (group_to_ips or {}).items():
            for ip in (arr or []):
                s = (ip or "").strip()
                if s:
                    ips.add(s)
    except Exception:
        return set()
    return ips



_DISPLAY_TZ = ZoneInfo("Asia/Bangkok")

# -----------------------------
# Pagination (Logs & Audit)
# -----------------------------
_PAGE_SIZE = 300  # rows per page

def _parse_page(v: str | None, *, default: int = 1) -> int:
    try:
        p = int((v or "").strip())
    except Exception:
        return int(default)
    if p < 1:
        return 1
    # hard cap to avoid silly offsets
    if p > 1000000:
        return 1000000
    return p

def _page_items(current: int, total_pages: int, *, radius: int = 2) -> list[int | None]:
    """Return a compact list of page numbers with None as an ellipsis marker."""
    tp = int(total_pages)
    cur = int(current)
    if tp <= 1:
        return [1]
    if tp <= 9:
        return list(range(1, tp + 1))

    items: list[int | None] = [1]

    start = max(2, cur - radius)
    end = min(tp - 1, cur + radius)

    if start > 2:
        items.append(None)

    for p in range(start, end + 1):
        items.append(p)

    if end < tp - 1:
        items.append(None)

    items.append(tp)
    return items

def _url_base(endpoint: str, args: dict[str, str | None], *, exclude: set[str]) -> str:
    """Build a URL (path + querystring) excluding some keys (e.g. current page)."""
    q: dict[str, str] = {}
    for k, v in (args or {}).items():
        if k in exclude:
            continue
        if v is None:
            continue
        if v == "" and k not in ("hide_noise", "auth_page", "cmd_page"):
            continue
        q[str(k)] = str(v)

    base = url_for(endpoint)
    if q:
        return base + "?" + urlencode(q)
    return base

def _format_epoch(ts: float) -> str:
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc).astimezone(_DISPLAY_TZ)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""

def _sqlite_available() -> bool:
    if not log_sqlite or not getattr(log_sqlite, "is_enabled", None) or not log_sqlite.is_enabled():
        return False
    try:
        dbp = log_sqlite.db_path()
        return bool(dbp and dbp.exists())
    except Exception:
        return False

def _sqlite_connect_ro() -> sqlite3.Connection:
    # Use a short timeout to avoid blocking the web page if indexer holds locks.
    conn = sqlite3.connect(str(log_sqlite.db_path()), timeout=2, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
    except Exception:
        pass
    return conn

def _sqlite_auth_page(
    *,
    page: int,
    page_size: int,
    start_dt: datetime | None,
    end_dt: datetime | None,
    user: str,
    device: str,
    result: str,
    group_ips: set[str],
    group_filter: str,
    hide_noise: bool,
    noise_users: set[str],
) -> tuple[list[dict], dict]:
    """Return (events_page, stats) for Auth tab from SQLite."""
    start_ts = float(start_dt.timestamp()) if start_dt else None
    end_ts = float(end_dt.timestamp()) if end_dt else None

    # If group filter selected but no devices in the group -> empty result.
    if group_filter and not group_ips:
        empty_stats = {
            "total": 0,
            "success": 0,
            "fail": 0,
            "uniq_users": 0,
            "uniq_devices": 0,
            "total_pages": 1,
            "page": 1,
            "page_items": [1],
            "page_start": 0,
            "page_end": 0,
            "has_prev": False,
            "has_next": False,
            "prev_page": 1,
            "next_page": 1,
        }
        return [], empty_stats

    where = ["source IN ('authc','authz','acct')"]
    params: list[object] = []

    if start_ts is not None and end_ts is not None:
        where.append("ts >= ? AND ts < ?")
        params.extend([start_ts, end_ts])

    u = (user or "").strip()
    d = (device or "").strip()
    r = (result or "").strip()
    if u:
        where.append("user = ?")
        params.append(u)
    if d:
        where.append("device = ?")
        params.append(d)
    if r:
        where.append("UPPER(result) = UPPER(?)")
        params.append(r)

    if group_filter:
        ips = sorted({(x or "").strip() for x in (group_ips or set()) if (x or "").strip()})
        if ips:
            ph = ",".join(["?"] * len(ips))
            where.append(f"device IN ({ph})")
            params.extend(ips)

    if hide_noise and noise_users:
        nu = sorted({(x or "").strip().lower() for x in (noise_users or set()) if (x or "").strip()})
        if nu:
            ph = ",".join(["?"] * len(nu))
            where.append(f"COALESCE(LOWER(user),'') NOT IN ({ph})")
            params.extend(nu)

    where_sql = " AND ".join(where)

    # Stats (full, not paged)
    sql_stats = f"""
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN UPPER(result) IN ('ACCEPT','OK','PASS','SUCCESS') THEN 1 ELSE 0 END) AS success,
          SUM(CASE WHEN UPPER(result) IN ('REJECT','FAIL','ERROR') THEN 1 ELSE 0 END) AS fail,
          COUNT(DISTINCT NULLIF(TRIM(user),'')) AS uniq_users,
          COUNT(DISTINCT NULLIF(TRIM(device),'')) AS uniq_devices
        FROM events
        WHERE {where_sql}
    """

    conn = _sqlite_connect_ro()
    try:
        row = conn.execute(sql_stats, tuple(params)).fetchone() or (0, 0, 0, 0, 0)
        total = int(row[0] or 0)
        success = int(row[1] or 0)
        fail = int(row[2] or 0)
        uniq_users = int(row[3] or 0)
        uniq_devices = int(row[4] or 0)

        total_pages = max(1, (total + int(page_size) - 1) // int(page_size))
        cur_page = int(page)
        if cur_page > total_pages:
            cur_page = total_pages
        if cur_page < 1:
            cur_page = 1

        offset = (cur_page - 1) * int(page_size)

        sql_page = f"""
            SELECT ts, user, device, action, result, raw, command
            FROM events
            WHERE {where_sql}
            ORDER BY ts DESC
            LIMIT ? OFFSET ?
        """
        page_rows = conn.execute(sql_page, tuple(params + [int(page_size), int(offset)])).fetchall()

    finally:
        try:
            conn.close()
        except Exception:
            pass

    events: list[dict] = []
    for ts, u2, d2, action, res, raw, cmd in page_rows:
        disp = _format_epoch(float(ts or 0.0))
        e = {
            "time": disp,
            "timestamp": disp,
            "user": u2 or "",
            "device": d2 or "",
            "action": action or "",
            "result": res or "",
            "raw": raw or "",
        }
        if cmd:
            e["command"] = cmd
        events.append(e)

    page_start = (offset + 1) if total > 0 and len(events) > 0 else 0
    page_end = offset + len(events) if total > 0 and len(events) > 0 else 0

    stats = {
        "total": total,
        "success": success,
        "fail": fail,
        "uniq_users": uniq_users,
        "uniq_devices": uniq_devices,
        "total_pages": total_pages,
        "page": cur_page,
        "page_items": _page_items(cur_page, total_pages),
        "page_start": page_start,
        "page_end": page_end,
        "has_prev": cur_page > 1,
        "has_next": cur_page < total_pages,
        "prev_page": max(1, cur_page - 1),
        "next_page": min(total_pages, cur_page + 1),
    }
    return events, stats

def _sqlite_command_page(
    *,
    page: int,
    page_size: int,
    start_dt: datetime | None,
    end_dt: datetime | None,
    cmd_user: str,
    cmd_device: str,
    cmd_contains: str,
    group_ips: set[str],
    group_filter: str,
    hide_noise: bool,
    noise_users: set[str],
) -> tuple[list[dict], dict, list[tuple[str, int]], list[dict]]:
    """Return (events_page, stats, top_users, user_activity) for Command tab from SQLite."""
    start_ts = float(start_dt.timestamp()) if start_dt else None
    end_ts = float(end_dt.timestamp()) if end_dt else None

    if group_filter and not group_ips:
        empty_stats = {
            "total": 0,
            "uniq_users": 0,
            "uniq_devices": 0,
            "total_pages": 1,
            "page": 1,
            "page_items": [1],
            "page_start": 0,
            "page_end": 0,
            "has_prev": False,
            "has_next": False,
            "prev_page": 1,
            "next_page": 1,
        }
        return [], empty_stats, [], []

    where = ["(command IS NOT NULL AND command != '')"]
    params: list[object] = []

    if start_ts is not None and end_ts is not None:
        where.append("ts >= ? AND ts < ?")
        params.extend([start_ts, end_ts])

    u = (cmd_user or "").strip()
    d = (cmd_device or "").strip()
    needle = (cmd_contains or "").strip().lower()
    if u:
        where.append("user = ?")
        params.append(u)
    if d:
        where.append("device = ?")
        params.append(d)
    if needle:
        where.append("(LOWER(command) LIKE ? OR LOWER(raw) LIKE ?)")
        like = f"%{needle}%"
        params.extend([like, like])

    if group_filter:
        ips = sorted({(x or "").strip() for x in (group_ips or set()) if (x or "").strip()})
        if ips:
            ph = ",".join(["?"] * len(ips))
            where.append(f"device IN ({ph})")
            params.extend(ips)

    if hide_noise and noise_users:
        nu = sorted({(x or "").strip().lower() for x in (noise_users or set()) if (x or "").strip()})
        if nu:
            ph = ",".join(["?"] * len(nu))
            where.append(f"COALESCE(LOWER(user),'') NOT IN ({ph})")
            params.extend(nu)

    where_sql = " AND ".join(where)

    sql_stats = f"""
        SELECT
          COUNT(*) AS total,
          COUNT(DISTINCT NULLIF(TRIM(user),'')) AS uniq_users,
          COUNT(DISTINCT NULLIF(TRIM(device),'')) AS uniq_devices
        FROM events
        WHERE {where_sql}
    """

    conn = _sqlite_connect_ro()
    try:
        row = conn.execute(sql_stats, tuple(params)).fetchone() or (0, 0, 0)
        total = int(row[0] or 0)
        uniq_users = int(row[1] or 0)
        uniq_devices = int(row[2] or 0)

        total_pages = max(1, (total + int(page_size) - 1) // int(page_size))
        cur_page = int(page)
        if cur_page > total_pages:
            cur_page = total_pages
        if cur_page < 1:
            cur_page = 1

        offset = (cur_page - 1) * int(page_size)

        sql_page = f"""
            SELECT ts, user, device, raw, command
            FROM events
            WHERE {where_sql}
            ORDER BY ts DESC
            LIMIT ? OFFSET ?
        """
        page_rows = conn.execute(sql_page, tuple(params + [int(page_size), int(offset)])).fetchall()

        # Top 10 users
        sql_top = f"""
            SELECT user, COUNT(*) AS c
            FROM events
            WHERE {where_sql} AND user IS NOT NULL AND TRIM(user) != ''
            GROUP BY user
            ORDER BY c DESC
            LIMIT 10
        """
        top_rows = conn.execute(sql_top, tuple(params)).fetchall()

        # User activity (all users, sorted)
        sql_act = f"""
            SELECT user, COUNT(*) AS c
            FROM events
            WHERE {where_sql} AND user IS NOT NULL AND TRIM(user) != ''
            GROUP BY user
            ORDER BY c DESC
        """
        act_rows = conn.execute(sql_act, tuple(params)).fetchall()

    finally:
        try:
            conn.close()
        except Exception:
            pass

    events: list[dict] = []
    for ts, u2, d2, raw, cmd in page_rows:
        disp = _format_epoch(float(ts or 0.0))
        events.append(
            {
                "time": disp,
                "timestamp": disp,
                "user": u2 or "",
                "device": d2 or "",
                "action": "command",
                "result": "",
                "raw": raw or "",
                "command": cmd or "",
            }
        )

    page_start = (offset + 1) if total > 0 and len(events) > 0 else 0
    page_end = offset + len(events) if total > 0 and len(events) > 0 else 0

    stats = {
        "total": total,
        "uniq_users": uniq_users,
        "uniq_devices": uniq_devices,
        "total_pages": total_pages,
        "page": cur_page,
        "page_items": _page_items(cur_page, total_pages),
        "page_start": page_start,
        "page_end": page_end,
        "has_prev": cur_page > 1,
        "has_next": cur_page < total_pages,
        "prev_page": max(1, cur_page - 1),
        "next_page": min(total_pages, cur_page + 1),
    }

    top_users = [(str(u3 or "").strip(), int(c or 0)) for (u3, c) in top_rows if (u3 or "").strip()]
    user_activity = [{"user": str(u3 or "").strip(), "count": int(c or 0)} for (u3, c) in act_rows if (u3 or "").strip()]
    return events, stats, top_users, user_activity

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



def _allowed_group_ids_from_session():
    """Return allowed device_group_ids for current session.
    - superadmin -> None (no restriction)
    - admin -> list of allowed group ids
    """
    role = (session.get("web_role") or "").strip().lower()
    web_username = (session.get("web_username") or "").strip()
    if not web_username:
        # Should not happen if routes are protected; fall back to no restriction
        return None
    if not role:
        role = "admin"
    try:
        return allowed_device_group_ids(role, web_username)
    except Exception:
        return None


_POLICY_CHOICES_CACHE: dict = {}

# Device group dropdown choices + device ip mapping (cached)
_GROUP_CHOICES_CACHE: dict = {}


def _get_device_groups_and_ips():
    """Return (groups, group_to_ips) from policy.json, restricted by admin scope.

    groups: list of {id, name}
    group_to_ips: dict[group_id] -> sorted list of device IPs
    """
    allowed = _allowed_group_ids_from_session()

    pol_mtime = 0.0
    try:
        if policy_store.POLICY_PATH.exists():
            pol_mtime = policy_store.POLICY_PATH.stat().st_mtime
    except Exception:
        pol_mtime = 0.0

    allowed_key = "__ALL__" if allowed is None else ",".join(sorted({(g or "").strip().lower() for g in (allowed or []) if (g or "").strip()}))
    cache_key = f"{pol_mtime:.3f}|{allowed_key}"
    cached = _GROUP_CHOICES_CACHE.get(cache_key)
    if cached and (time.time() - float(cached.get('ts') or 0.0)) < 2.0:
        return cached.get('groups') or [], cached.get('group_to_ips') or {}

    policy = policy_store.load_policy() or {}
    groups_raw = policy.get('device_groups') or []
    devices_raw = policy.get('devices') or []

    groups = []
    for g in groups_raw:
        if not isinstance(g, dict):
            continue
        gid = (g.get('id') or '').strip().lower()
        if not gid:
            continue
        name = (g.get('name') or gid).strip() or gid
        groups.append({'id': gid, 'name': name})

    groups.sort(key=lambda x: (x.get('name') or x.get('id') or ''))

    group_to_ips = {}
    for d in devices_raw:
        if not isinstance(d, dict):
            continue
        gid = (d.get('group_id') or '').strip().lower()
        ip = (d.get('ip') or '').strip()
        if not gid or not ip:
            continue
        group_to_ips.setdefault(gid, set()).add(ip)

    if allowed is not None:
        allowed_set = set((g or '').strip().lower() for g in (allowed or []) if (g or '').strip())
        groups = [g for g in groups if g.get('id') in allowed_set]
        group_to_ips = {gid: ips for gid, ips in group_to_ips.items() if gid in allowed_set}

    group_to_ips_sorted = {gid: sorted(ips) for gid, ips in group_to_ips.items()}

    _GROUP_CHOICES_CACHE[cache_key] = {
        'ts': time.time(),
        'groups': groups,
        'group_to_ips': group_to_ips_sorted,
    }
    return groups, group_to_ips_sorted


def _filter_events_by_group(events: list[dict], group_ips: set[str]) -> list[dict]:
    if not events:
        return events
    if not group_ips:
        # group filter is active but group has no devices -> no results
        return []
    out = []
    for e in events:
        dev = (e.get('device') or '').strip()
        if dev and dev in group_ips:
            out.append(e)
    return out


_USER_GROUP_CACHE: dict[str, dict] = {}


def _narrow_user_list_to_group(
    user_list: list[str],
    *,
    group_id: str,
    group_ips: set[str],
    selected_user: str,
) -> list[str]:
    """Narrow policy-based user dropdown list to the selected device group.

    Strategy (stable + fast):
      - Start from policy-based user_list (already scope-restricted for admin accounts)
      - Keep users that are:
          * global (no device_group_ids) OR
          * explicitly include group_id OR
          * have target_olt_ips intersecting devices in the group

    This keeps dropdown options stable (not dependent on recent log samples).
    """
    gid = (group_id or "").strip().lower()
    if not gid:
        return user_list

    # If group filter is active but group has no devices -> no meaningful users.
    if not group_ips:
        out: list[str] = []
        sel = (selected_user or "").strip()
        if sel:
            out.append(sel)
        return out

    # Cache by policy mtime + group_id (micro TTL to avoid refresh storms)
    pol_mtime = 0.0
    try:
        if policy_store.POLICY_PATH.exists():
            pol_mtime = policy_store.POLICY_PATH.stat().st_mtime
    except Exception:
        pol_mtime = 0.0

    ck = f"{pol_mtime:.3f}|{gid}"
    cached = _USER_GROUP_CACHE.get(ck)
    if cached and (time.time() - float(cached.get("ts") or 0.0)) < 2.0:
        eligible = set(cached.get("eligible") or [])
    else:
        policy = policy_store.load_policy() or {}
        users = policy.get("users") or []
        eligible: set[str] = set()
        for u in users:
            if not isinstance(u, dict):
                continue
            uname = (u.get("username") or "").strip()
            if not uname:
                continue

            gids = [str(x).strip().lower() for x in (u.get("device_group_ids") or []) if str(x).strip()]
            # global users (no device_group_ids)
            if len(gids) == 0:
                eligible.add(uname)
                continue
            if gid in set(gids):
                eligible.add(uname)
                continue

            # Target OLT scope can still make a user relevant to this group
            t_ips = {str(x).strip() for x in (u.get("target_olt_ips") or []) if str(x).strip()}
            if t_ips and (t_ips & group_ips):
                eligible.add(uname)

        _USER_GROUP_CACHE[ck] = {"ts": time.time(), "eligible": sorted(eligible)}

    # Preserve existing ordering (already sorted) from policy-based list
    out = [u for u in (user_list or []) if u in eligible]

    # Keep selected value visible even if it doesn't match current group (backward compatibility)
    sel = (selected_user or "").strip()
    if sel and sel not in out:
        out.append(sel)
    return out


# -----------------------------
# Result dropdown choices
# -----------------------------

_RESULT_CHOICES_CACHE: dict[str, dict] = {}


def _canonical_auth_results() -> list[str]:
    # Keep commonly-seen values first; allow extras from DB/files to follow.
    return ["ACCEPT", "REJECT", "OK"]


def _sqlite_distinct_results(*, start_dt: datetime | None, end_dt: datetime | None) -> set[str]:
    """Return DISTINCT result values from SQLite (if enabled).

    We scope by auth/session sources (authc/authz/acct/conn) and optional time range.
    """
    if not log_sqlite or not getattr(log_sqlite, "is_enabled", None) or not log_sqlite.is_enabled():
        return set()

    try:
        dbp = log_sqlite.db_path()
        if not dbp.exists():
            return set()

        # Cache key uses DB mtime + optional range to avoid repeated DB hits on refresh storms.
        mtime = 0.0
        try:
            mtime = dbp.stat().st_mtime
        except Exception:
            mtime = 0.0

        start_ts = float(start_dt.timestamp()) if start_dt else 0.0
        end_ts = float(end_dt.timestamp()) if end_dt else 0.0
        ck = f"{mtime:.3f}|{start_ts:.0f}|{end_ts:.0f}"
        cached = _RESULT_CHOICES_CACHE.get(ck)
        if cached and (time.time() - float(cached.get("ts") or 0.0)) < 5.0:
            return set(cached.get("vals") or [])

        q = """
            SELECT DISTINCT result
            FROM events
            WHERE result IS NOT NULL AND TRIM(result) != ''
              AND source IN ('authc','authz','acct')
        """
        params: list[object] = []
        if start_dt and end_dt:
            q += " AND ts >= ? AND ts < ?"
            params.extend([start_ts, end_ts])

        vals: set[str] = set()
        conn = sqlite3.connect(str(dbp), timeout=2, check_same_thread=False)
        try:
            for (r,) in conn.execute(q, params).fetchall():
                s = (r or "").strip().upper()
                if s:
                    vals.add(s)
        finally:
            try:
                conn.close()
            except Exception:
                pass

        _RESULT_CHOICES_CACHE[ck] = {"ts": time.time(), "vals": sorted(vals)}
        return vals
    except Exception:
        return set()


def _build_auth_result_list(
    *,
    events_for_lists: list[dict],
    start_dt: datetime | None,
    end_dt: datetime | None,
    selected: str,
) -> list[str]:
    """Build Result dropdown list.

    Goal: show all meaningful Result values (not only the most recent limited sample),
    similar to User/Device dropdowns which are policy-based.
    """
    observed: set[str] = set()

    # From currently-parsed events (covers cases before SQLite ingest catches up)
    for e in (events_for_lists or []):
        r = (e.get("result") or "").strip().upper()
        if r:
            observed.add(r)

    # From SQLite distinct results (fast and stable)
    observed |= _sqlite_distinct_results(start_dt=start_dt, end_dt=end_dt)

    canonical = _canonical_auth_results()
    canon_set = set(canonical)

    # Keep canonical ordering first, then any extra values alphabetically.
    extra = sorted(v for v in observed if v not in canon_set)
    out: list[str] = []
    for v in canonical:
        # include canonical always, so UI consistently shows all expected result types
        out.append(v)
    out.extend(extra)

    # Ensure currently-selected value is visible even if it isn't in any source (backward compatibility)
    sel = (selected or "").strip().upper()
    if sel and sel not in out:
        out.append(sel)
    return out


def _get_filter_choices_from_policy():
    """Build dropdown choices from policy.json (not from recent logs).

    This prevents 'missing options' when recent log sample is too small.
    Choices are also restricted by device-group scope for admin accounts.
    """
    allowed = _allowed_group_ids_from_session()

    # Cache by (policy mtime, allowed groups) to reduce per-refresh overhead.
    pol_mtime = 0.0
    try:
        if policy_store.POLICY_PATH.exists():
            pol_mtime = policy_store.POLICY_PATH.stat().st_mtime
    except Exception:
        pol_mtime = 0.0

    allowed_key = "__ALL__" if allowed is None else ",".join(sorted({(g or "").strip().lower() for g in (allowed or []) if (g or "").strip()}))
    cache_key = f"{pol_mtime:.3f}|{allowed_key}"
    cached = _POLICY_CHOICES_CACHE.get(cache_key)
    if cached and (time.time() - float(cached.get("ts") or 0.0)) < 2.0:
        return cached.get("users") or [], cached.get("devices") or []

    policy = policy_store.load_policy() or {}
    users = policy.get("users") or []
    devices = policy.get("devices") or []

    # Noise/users to hide in dropdown (does not affect DB; just UI lists)
    noise_users, _default_hide = _get_noise_users()

    if allowed is None:
        device_list = sorted({(d.get("ip") or "").strip() for d in devices if (d.get("ip") or "").strip()})
        user_list = sorted({(u.get("username") or "").strip() for u in users if (u.get("username") or "").strip()})
    else:
        allowed_set = set((g or "").strip().lower() for g in (allowed or []) if (g or "").strip())

        # Allowed device IPs for the admin's scope
        device_list = sorted(
            {(d.get("ip") or "").strip() for d in devices if (d.get("ip") or "").strip() and device_in_scope(d, allowed_set)}
        )
        allowed_ips = set(device_list)

        user_list = []
        for u in users:
            uname = (u.get("username") or "").strip()
            if not uname:
                continue

            gids = [str(x).strip().lower() for x in (u.get("device_group_ids") or []) if str(x).strip()]

            # Backward compatible / "global" users:
            # - If device_group_ids is missing/empty, treat as global (visible to all admins)
            in_scope = (len(gids) == 0)

            if not in_scope and (set(gids) & allowed_set):
                in_scope = True

            # Target OLT scope can grant visibility even if groups aren't set
            if not in_scope:
                t_ips = [str(x).strip() for x in (u.get("target_olt_ips") or []) if str(x).strip()]
                if t_ips and any(ip in allowed_ips for ip in t_ips):
                    in_scope = True

            if in_scope:
                user_list.append(uname)
        user_list = sorted(set(user_list))

    # Hide noisy/system accounts in dropdown
    user_list = [u for u in user_list if (u or "").strip().lower() not in noise_users]

    _POLICY_CHOICES_CACHE[cache_key] = {"ts": time.time(), "users": user_list, "devices": device_list}
    return user_list, device_list


def _filter_out_noise(events: list[dict], noise_users: set[str]) -> list[dict]:
    if not events or not noise_users:
        return events
    out = []
    for e in events:
        u = (e.get("user") or "").strip().lower()
        if u and u in noise_users:
            continue
        out.append(e)
    return out

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
    # Pagination (separate params for each tab to avoid collisions)
    auth_page = _parse_page(request.args.get("auth_page") or request.args.get("page"), default=1)
    cmd_page = _parse_page(request.args.get("cmd_page"), default=1)

    # Filters
    user_filter, device_filter, result_filter = _get_auth_filters()
    cmd_user_filter, cmd_device_filter, cmd_contains_filter = _get_cmd_filters()
    date_from, date_to, start_dt, end_dt = _get_date_filters()

    group_filter = _get_group_filter()
    group_list, group_to_ips = _get_device_groups_and_ips()
    group_ips = set(group_to_ips.get(group_filter, [])) if group_filter else set()

    # Enforce admin visibility scope even when no group is selected.
    # - superadmin -> no restriction
    # - admin -> only devices in their allowed groups
    scope_ips = _scope_device_ips_for_admin(group_to_ips=group_to_ips)
    query_group_filter = group_filter
    query_group_ips = group_ips
    if not group_filter and scope_ips is not None:
        # Reuse the existing "group" filter path in SQLite/file-scan code
        # without changing UI state.
        query_group_filter = "__scope__"
        query_group_ips = scope_ips

    noise_users, default_hide_noise = _get_noise_users()
    hn_vals = request.args.getlist("hide_noise")
    hide_noise = _parse_bool(hn_vals[-1] if hn_vals else None, default=default_hide_noise)

    # Dropdown lists (from policy.json so options never get 'pushed out')
    user_list, device_list = _get_filter_choices_from_policy()
    if group_filter:
        # Narrow user/device dropdowns to the selected group (UX)
        user_list = _narrow_user_list_to_group(
            user_list,
            group_id=group_filter,
            group_ips=group_ips,
            selected_user=user_filter,
        )
        d2 = [d for d in (device_list or []) if d in group_ips] if group_ips else []
        if device_filter and device_filter not in d2:
            d2.append(device_filter)
        device_list = d2

    # Base args for pagination links
    _base_args = {
        "group": (group_filter or ""),
        "user": (user_filter or ""),
        "device": (device_filter or ""),
        "result": (result_filter or ""),
        "cmd_user": (cmd_user_filter or ""),
        "cmd_device": (cmd_device_filter or ""),
        "cmd_contains": (cmd_contains_filter or ""),
        "date_from": (date_from or ""),
        "date_to": (date_to or ""),
        # always keep explicit toggle value stable across pages
        "hide_noise": ("1" if hide_noise else "0"),
        # preserve the other tab's page so switching tabs doesn't lose it
        "cmd_page": str(cmd_page),
    }
    auth_page_url_base = _url_base("logs.auth", _base_args, exclude={"auth_page"})

    # Prefer SQLite for correct historical pagination (no 6000-cap)
    use_sqlite = _sqlite_available()

    if use_sqlite:
        # Trigger quick ingest (fast) so the DB is up-to-date for the latest files
        try:
            get_recent_events(
                limit=1,
                start_dt=start_dt,
                end_dt=end_dt,
                user=user_filter,
                device=device_filter,
                result=result_filter,
            )
        except Exception:
            pass

        page_events, stats = _sqlite_auth_page(
            page=auth_page,
            page_size=_PAGE_SIZE,
            start_dt=start_dt,
            end_dt=end_dt,
            user=user_filter,
            device=device_filter,
            result=result_filter,
            group_ips=query_group_ips,
            group_filter=query_group_filter,
            hide_noise=hide_noise,
            noise_users=noise_users,
        )
        auth_page = int(stats["page"])

        # Summary (full match count, not just current page)
        total_events = int(stats["total"])
        total_success = int(stats["success"])
        total_fail = int(stats["fail"])
        unique_user_count = int(stats["uniq_users"])
        unique_device_count = int(stats["uniq_devices"])

        recent_events = page_events
        events_for_lists = page_events

        auth_total_pages = int(stats["total_pages"])
        auth_page_items = stats["page_items"]
        auth_has_prev = bool(stats["has_prev"])
        auth_has_next = bool(stats["has_next"])
        auth_prev_page = int(stats["prev_page"])
        auth_next_page = int(stats["next_page"])
        auth_page_start = int(stats["page_start"])
        auth_page_end = int(stats["page_end"])

    else:
        # Fallback (file scan): keep existing behavior but paginate the result list
        if start_dt and end_dt:
            dropdown_events = get_recent_events(limit=6000, start_dt=start_dt, end_dt=end_dt)

            if user_filter or device_filter or result_filter:
                filtered_events = get_recent_events(
                    limit=6000,
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
            has_any_filter = bool(user_filter or device_filter or result_filter or group_filter)

            if not has_any_filter:
                base_limit = 400
                base_max_files = 4
                base_max_lines = 6000

                events_for_lists = _get_recent_auth_events_cached(
                    limit=base_limit,
                    max_files=base_max_files,
                    max_lines_each=base_max_lines,
                )
                filtered_events = events_for_lists
            else:
                base_limit = 6000
                base_max_files = 90
                base_max_lines = 12000

                dropdown_events = get_recent_events(
                    limit=base_limit,
                    max_files=base_max_files,
                    max_lines_each=base_max_lines,
                )
                events_for_lists = dropdown_events

                filtered_events = get_recent_events(
                    limit=base_limit,
                    max_files=base_max_files,
                    max_lines_each=base_max_lines,
                    user=user_filter,
                    device=device_filter,
                    result=result_filter,
                )

        if hide_noise:
            filtered_events = _filter_out_noise(filtered_events, noise_users)
            events_for_lists = _filter_out_noise(events_for_lists, noise_users)

        # Enforce admin scope (even when no group is selected)
        if query_group_filter:
            filtered_events = _filter_events_by_group(filtered_events, query_group_ips)
            events_for_lists = _filter_events_by_group(events_for_lists, query_group_ips)

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

        auth_total_pages = max(1, (total_events + _PAGE_SIZE - 1) // _PAGE_SIZE)
        if auth_page > auth_total_pages:
            auth_page = auth_total_pages
        if auth_page < 1:
            auth_page = 1
        offset = (auth_page - 1) * _PAGE_SIZE
        recent_events = filtered_events[offset : offset + _PAGE_SIZE]

        auth_page_items = _page_items(auth_page, auth_total_pages)
        auth_has_prev = auth_page > 1
        auth_has_next = auth_page < auth_total_pages
        auth_prev_page = max(1, auth_page - 1)
        auth_next_page = min(auth_total_pages, auth_page + 1)
        auth_page_start = (offset + 1) if total_events > 0 and len(recent_events) > 0 else 0
        auth_page_end = offset + len(recent_events) if total_events > 0 and len(recent_events) > 0 else 0

    result_list = _build_auth_result_list(
        events_for_lists=events_for_lists,
        start_dt=start_dt,
        end_dt=end_dt,
        selected=result_filter,
    )

    return render_template(
        "logs_auth.html",
        active_page="logs",
        active_logs_subpage="auth",
        # data (paged)
        recent_events=recent_events,
        # summary (full match count)
        total_events=total_events,
        total_success=total_success,
        total_fail=total_fail,
        unique_user_count=unique_user_count,
        unique_device_count=unique_device_count,
        # pagination
        auth_page=auth_page,
        cmd_page=cmd_page,
        auth_total_pages=auth_total_pages,
        auth_page_items=auth_page_items,
        auth_has_prev=auth_has_prev,
        auth_has_next=auth_has_next,
        auth_prev_page=auth_prev_page,
        auth_next_page=auth_next_page,
        auth_page_start=auth_page_start,
        auth_page_end=auth_page_end,
        auth_page_url_base=auth_page_url_base,
        # device group filter
        group_list=group_list,
        group_filter=group_filter,
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
        hide_noise=hide_noise,
    )



@bp.route("/command")
def command():
    # Pagination (separate params for each tab to avoid collisions)
    cmd_page = _parse_page(request.args.get("cmd_page") or request.args.get("page"), default=1)
    auth_page = _parse_page(request.args.get("auth_page"), default=1)

    # Filters (preserve auth filters so the user doesn't lose state)
    user_filter, device_filter, result_filter = _get_auth_filters()
    cmd_user_filter, cmd_device_filter, cmd_contains_filter = _get_cmd_filters()
    group_filter = _get_group_filter()
    group_list, group_to_ips = _get_device_groups_and_ips()
    group_ips = set(group_to_ips.get(group_filter, [])) if group_filter else set()

    # Enforce admin visibility scope even when no group is selected.
    # - superadmin -> no restriction
    # - admin -> only devices in their allowed groups
    scope_ips = _scope_device_ips_for_admin(group_to_ips=group_to_ips)
    query_group_filter = group_filter
    query_group_ips = group_ips
    if not group_filter and scope_ips is not None:
        # Reuse the existing "group" filter path in SQLite/file-scan code
        # without changing UI state.
        query_group_filter = "__scope__"
        query_group_ips = scope_ips

    date_from, date_to, start_dt, end_dt = _get_date_filters()

    noise_users, default_hide_noise = _get_noise_users()
    hn_vals = request.args.getlist("hide_noise")
    hide_noise = _parse_bool(hn_vals[-1] if hn_vals else None, default=default_hide_noise)

    # "Mode" badge (kept for UI compatibility)
    scan_all_cmd = bool(
        cmd_user_filter or cmd_device_filter or cmd_contains_filter or group_filter or (start_dt and end_dt)
    )

    # Dropdown lists (from policy.json so options never get 'pushed out')
    cmd_user_list, cmd_device_list = _get_filter_choices_from_policy()
    if group_filter:
        cmd_user_list = _narrow_user_list_to_group(
            cmd_user_list,
            group_id=group_filter,
            group_ips=group_ips,
            selected_user=cmd_user_filter,
        )
        d2 = [d for d in (cmd_device_list or []) if d in group_ips] if group_ips else []
        if cmd_device_filter and cmd_device_filter not in d2:
            d2.append(cmd_device_filter)
        cmd_device_list = d2

    # Base args for pagination links
    _base_args = {
        "group": (group_filter or ""),
        "cmd_user": (cmd_user_filter or ""),
        "cmd_device": (cmd_device_filter or ""),
        "cmd_contains": (cmd_contains_filter or ""),
        "date_from": (date_from or ""),
        "date_to": (date_to or ""),
        "hide_noise": ("1" if hide_noise else "0"),
        # preserve auth filters and the other tab's page
        "user": (user_filter or ""),
        "device": (device_filter or ""),
        "result": (result_filter or ""),
        "auth_page": str(auth_page),
    }
    cmd_page_url_base = _url_base("logs.command", _base_args, exclude={"cmd_page"})

    use_sqlite = _sqlite_available()

    if use_sqlite:
        # Trigger quick ingest so DB is fresh (fast)
        try:
            get_command_events(
                limit=1,
                scan_all=False,
                user=cmd_user_filter,
                device=cmd_device_filter,
                contains=cmd_contains_filter,
                start_dt=start_dt,
                end_dt=end_dt,
            )
        except Exception:
            pass

        page_events, stats, top_users, user_activity = _sqlite_command_page(
            page=cmd_page,
            page_size=_PAGE_SIZE,
            start_dt=start_dt,
            end_dt=end_dt,
            cmd_user=cmd_user_filter,
            cmd_device=cmd_device_filter,
            cmd_contains=cmd_contains_filter,
            group_ips=query_group_ips,
            group_filter=query_group_filter,
            hide_noise=hide_noise,
            noise_users=noise_users,
        )
        cmd_page = int(stats["page"])

        command_events = page_events
        total_cmd = int(stats["total"])
        cmd_unique_user_count = int(stats["uniq_users"])
        cmd_unique_device_count = int(stats["uniq_devices"])
        cmd_user_breakdown = top_users
        cmd_user_activity = user_activity

        cmd_total_pages = int(stats["total_pages"])
        cmd_page_items = stats["page_items"]
        cmd_has_prev = bool(stats["has_prev"])
        cmd_has_next = bool(stats["has_next"])
        cmd_prev_page = int(stats["prev_page"])
        cmd_next_page = int(stats["next_page"])
        cmd_page_start = int(stats["page_start"])
        cmd_page_end = int(stats["page_end"])

    else:
        # Fallback (file scan): keep existing behavior but paginate the result list
        if scan_all_cmd:
            all_events = get_command_events(
                limit=6000,
                scan_all=True,
                user=cmd_user_filter,
                device=cmd_device_filter,
                contains=cmd_contains_filter,
                start_dt=start_dt,
                end_dt=end_dt,
            )
        else:
            all_events = _get_recent_cmd_events_cached(limit=400)

        if hide_noise:
            all_events = _filter_out_noise(all_events, noise_users)

        if query_group_filter:
            all_events = _filter_events_by_group(all_events, query_group_ips)

        total_cmd = len(all_events)
        cmd_unique_user_count = len({e.get("user") for e in all_events if e.get("user")})
        cmd_unique_device_count = len({e.get("device") for e in all_events if e.get("device")})

        cmd_user_breakdown = Counter(
            (e.get("user") or "").strip() for e in all_events if (e.get("user") or "").strip()
        ).most_common(10)

        cmd_user_activity = [
            {"user": u, "count": n}
            for u, n in Counter(
                (e.get("user") or "").strip() for e in all_events if (e.get("user") or "").strip()
            ).most_common()
        ]

        cmd_total_pages = max(1, (total_cmd + _PAGE_SIZE - 1) // _PAGE_SIZE)
        if cmd_page > cmd_total_pages:
            cmd_page = cmd_total_pages
        if cmd_page < 1:
            cmd_page = 1
        offset = (cmd_page - 1) * _PAGE_SIZE
        command_events = all_events[offset : offset + _PAGE_SIZE]

        cmd_page_items = _page_items(cmd_page, cmd_total_pages)
        cmd_has_prev = cmd_page > 1
        cmd_has_next = cmd_page < cmd_total_pages
        cmd_prev_page = max(1, cmd_page - 1)
        cmd_next_page = min(cmd_total_pages, cmd_page + 1)
        cmd_page_start = (offset + 1) if total_cmd > 0 and len(command_events) > 0 else 0
        cmd_page_end = offset + len(command_events) if total_cmd > 0 and len(command_events) > 0 else 0

    return render_template(
        "logs_command.html",
        active_page="logs",
        active_logs_subpage="command",
        # command data (paged)
        command_events=command_events,
        total_cmd=total_cmd,
        cmd_unique_user_count=cmd_unique_user_count,
        cmd_unique_device_count=cmd_unique_device_count,
        cmd_user_breakdown=cmd_user_breakdown,
        cmd_user_activity=cmd_user_activity,
        scan_all_cmd=scan_all_cmd,
        # pagination
        auth_page=auth_page,
        cmd_page=cmd_page,
        cmd_total_pages=cmd_total_pages,
        cmd_page_items=cmd_page_items,
        cmd_has_prev=cmd_has_prev,
        cmd_has_next=cmd_has_next,
        cmd_prev_page=cmd_prev_page,
        cmd_next_page=cmd_next_page,
        cmd_page_start=cmd_page_start,
        cmd_page_end=cmd_page_end,
        cmd_page_url_base=cmd_page_url_base,
        # device group filter
        group_list=group_list,
        group_filter=group_filter,
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
        hide_noise=hide_noise,
    )



@bp.route("/filter_choices")
def filter_choices_api():
    """AJAX helper: return dropdown choices for User/Device based on Device Group.

    - Uses policy.json (stable) and admin scope restriction.
    - Does NOT depend on recent logs, so options won't disappear.
    """
    group_id = (request.args.get("group") or "").strip().lower()

    # base choices (scope-restricted)
    user_list, device_list = _get_filter_choices_from_policy()

    # group -> ips mapping (scope-restricted)
    _groups, group_to_ips = _get_device_groups_and_ips()
    group_ips = set(group_to_ips.get(group_id, [])) if group_id else set()

    if group_id:
        # Narrow devices to only the selected group
        device_list = sorted(group_ips)
        # Narrow users to those relevant to this group (global / in-group / target-OLT intersects)
        user_list = _narrow_user_list_to_group(
            user_list,
            group_id=group_id,
            group_ips=group_ips,
            selected_user="",  # for AJAX we reset if no longer valid
        )

    return jsonify({"users": user_list, "devices": device_list})

