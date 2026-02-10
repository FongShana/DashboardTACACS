# tacacs_dashboard/services/log_parser.py
from __future__ import annotations

from pathlib import Path
import re
from datetime import datetime, timezone, date, timedelta
from collections import Counter
from typing import Optional, Iterable
from collections import deque
import heapq
from zoneinfo import ZoneInfo

# Optional SQLite index (fast log search). Falls back to file scanning if disabled.
try:
    from . import log_sqlite
except Exception:  # pragma: no cover
    log_sqlite = None

DISPLAY_TZ = ZoneInfo("Asia/Bangkok")  # UTC+7

LOG_DIR = Path("/var/log/tac_plus")

# ---------- regex helpers ----------
IP_RE = r"(?:\d{1,3}\.){3}\d{1,3}"

TS_PREFIX_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"(?:\s+(?P<tz>[+-]\d{4}))?\s+"
    r"(?P<msg>.+)$"
)

CONN_RE = re.compile(
    rf"^(?P<op>start|stop)\s+tcp\s+(?P<device>{IP_RE})\s+\d+\s+(?P<src>{IP_RE})\s+(?P<port>\d+)\s*$",
    re.IGNORECASE,
)

# authc ตัวอย่าง: "10.235.110.28 ascii login for 'eng_bkk' from 10.235.110.100 on vty0 succeeded ..."
AUTHC_LOGIN_RE = re.compile(
    rf"^(?P<device>{IP_RE}).*?\bascii\s+login\s+for\s+['\"](?P<user>[^'\"]+)['\"].*?\bfrom\s+(?P<src>{IP_RE}).*?\b(?P<res>succeeded|failed|reject|rejected|deny|denied|error)\b",
    re.IGNORECASE,
)

AUTHC_LOGOUT_RE = re.compile(
    rf"^(?P<device>{IP_RE}).*?\blogout\b.*?\bfor\b\s+['\"](?P<user>[^'\"]+)['\"].*?\bfrom\b\s+(?P<src>{IP_RE})",
    re.IGNORECASE,
)

# new template for authc log 
AUTHC_COL_RE = re.compile(
    rf"^(?P<device>{IP_RE})\s+(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<src>{IP_RE})\s+(?P<rest>.+)$",
    re.IGNORECASE,
)

# acct ตัวอย่างของคุณ:
# 2025-12-24 01:40:33 +0000 10.235.110.28 eng_bkk vty0 10.235.110.100 stop shell aaa-accounting-template 1
ACCT_RE = re.compile(
    rf"^(?P<device>{IP_RE})\s+(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<src>{IP_RE})\s+(?P<op>start|stop)\s+(?P<service>\S+)\s+(?P<cmd>.+)$",
    re.IGNORECASE,
)

# authz format จริงอาจต่างกันระหว่าง vendor — ทำเป็น generic จับ device/user/src ได้ก่อน
AUTHZ_GENERIC_RE = re.compile(
    rf"^(?P<device>{IP_RE})\s+(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<src>{IP_RE})\s+(?P<rest>.+)$",
    re.IGNORECASE,
)

# ---------- core utils ----------
def _split_ts(line: str) -> tuple[Optional[datetime], str, str]:
    """
    return: (dt_utc_or_none, time_str, msg_after_timestamp)
    time_str ใช้โชว์ในหน้าเว็บ
    """
    s = line.strip()
    m = TS_PREFIX_RE.match(s)
    if not m:
        # ไม่มี prefix เวลา -> time ว่าง แต่ยังลอง parse msg ได้
        return None, "", s

    ts = m.group("ts")
    tz = (m.group("tz") or "").strip()
    msg = (m.group("msg") or "").strip()

    dt = None
    try:
        if tz:
            dt = datetime.strptime(f"{ts} {tz}", "%Y-%m-%d %H:%M:%S %z")
        else:
            # ถ้าไม่มี tz ในบรรทัด ให้ถือว่าเป็น UTC (ตามเคสคุณ)
            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        dt = None

    if dt:
        dt_local = dt.astimezone(DISPLAY_TZ)
        time_str = dt_local.strftime("%Y-%m-%d %H:%M:%S")
        return dt_local, time_str, msg

    # fallback
    time_str = ts
    return None, time_str, msg

def _event(
    *,
    dt: Optional[datetime],
    time_str: str,
    user: str = "",
    device: str = "",
    action: str = "",
    result: str = "",
    raw: str = "",
    command: str = "",
) -> dict:
    # ใส่ทั้ง time และ timestamp กัน template คนละชื่อ
    e = {
        "time": time_str or "",
        "timestamp": time_str or "",
        "user": user or "",
        "device": device or "",
        "action": action or "",
        "result": result or "",
        "raw": raw or "",
    }
    if command:
        e["command"] = command
    # key สำหรับ sort ภายใน
    e["_ts"] = dt.timestamp() if dt else 0.0
    return e


def _read_recent_lines(files: list[Path], max_lines_each: int = 2000) -> Iterable[str]:
    """Yield non-empty lines from files.

    Streaming implementation to avoid loading entire files into memory.

    max_lines_each behavior:
      - max_lines_each > 0 : take only last N non-empty lines (tail) per file
      - max_lines_each <= 0: read ALL non-empty lines in the file
    """
    take_tail = int(max_lines_each) > 0
    tail_n = int(max_lines_each) if take_tail else 0

    for p in files:
        try:
            if take_tail:
                dq: deque[str] = deque(maxlen=tail_n)
                with p.open("r", encoding="utf-8", errors="ignore") as f:
                    for raw in f:
                        line = raw.rstrip("\n")
                        if line.strip():
                            dq.append(line)
                for line in dq:
                    yield line
            else:
                with p.open("r", encoding="utf-8", errors="ignore") as f:
                    for raw in f:
                        line = raw.rstrip("\n")
                        if line.strip():
                            yield line
        except Exception:
            continue


def _all_files(glob_pat: str) -> list[Path]:
    """Return all matching log files, newest first."""
    return sorted(LOG_DIR.glob(glob_pat), key=lambda x: x.stat().st_mtime, reverse=True)


def _latest_files(glob_pat: str, max_files: int = 4) -> list[Path]:
    files = sorted(LOG_DIR.glob(glob_pat), key=lambda x: x.stat().st_mtime, reverse=True)
    return files[:max_files]


def _filename_date(p: Path) -> date | None:
    """Extract YYYY-MM-DD from log filename like authc-2026-02-09.log"""
    m = re.search(r"-(\d{4}-\d{2}-\d{2})\.log$", p.name)
    if not m:
        return None
    try:
        return date.fromisoformat(m.group(1))
    except Exception:
        return None


def _files_for_range(glob_pat: str, start_dt: datetime, end_dt: datetime, *, buffer_days: int = 1) -> list[Path]:
    """Select daily log files by filename date within [start, end) (local), with a small buffer."""
    if not LOG_DIR.exists():
        return []
    if not start_dt or not end_dt:
        return []

    # Convert [start, end) to date range inclusive on filenames
    start_d = (start_dt.date() - timedelta(days=int(buffer_days)))
    end_d_inclusive = ((end_dt.date()) + timedelta(days=int(buffer_days)))

    out: list[Path] = []
    for p in LOG_DIR.glob(glob_pat):
        fd = _filename_date(p)
        if not fd:
            continue
        if start_d <= fd <= end_d_inclusive:
            out.append(p)

    # Prefer newest first (consistent with existing behavior)
    try:
        out.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    except Exception:
        out = sorted(out, reverse=True)
    return out



# ---------- parsers ----------
def _parse_conn(line: str) -> Optional[dict]:
    dt, time_str, msg = _split_ts(line)
    m = CONN_RE.match(msg)
    if not m:
        return None
    op = m.group("op").lower()
    device = m.group("device")
    src = m.group("src")
    action = f"conn_{op}"
    return _event(dt=dt, time_str=time_str, user="", device=device, action=action, result="", raw=line.strip())


def _parse_authc(line: str) -> Optional[dict]:
    dt, time_str, msg = _split_ts(line)

    # --- แบบเก่า: "... ascii login for 'user' from ... succeeded/failed" ---
    m = AUTHC_LOGIN_RE.match(msg)
    if m:
        device = m.group("device")
        user = m.group("user")
        res = (m.group("res") or "").lower()
        result = "ACCEPT" if "succeed" in res else "REJECT"
        return _event(
            dt=dt,
            time_str=time_str,
            user=user,
            device=device,
            action="login",
            result=result,
            raw=msg,
        )

    m = AUTHC_LOGOUT_RE.match(msg)
    if m:
        device = m.group("device")
        user = m.group("user")
        return _event(
            dt=dt,
            time_str=time_str,
            user=user,
            device=device,
            action="logout",
            result="OK",
            raw=line.strip(),
        )

    # --- ✅ แบบใหม่ (แบบที่คุณมี): "<device> <user> <tty> <src> ascii login succeeded/failed" ---
    m = AUTHC_COL_RE.match(msg)
    if not m:
        return None

    device = m.group("device")
    user = m.group("user")
    rest = (m.group("rest") or "").strip()
    rest_l = rest.lower()

    # login
    if rest_l.startswith("ascii login"):
        if "succeed" in rest_l or "success" in rest_l:
            result = "ACCEPT"
        elif "fail" in rest_l or "deny" in rest_l or "reject" in rest_l:
            result = "REJECT"
        else:
            result = ""
        return _event(
            dt=dt,
            time_str=time_str,
            user=user,
            device=device,
            action="login",
            result=result,
            raw=msg,
        )

    # enable (ถ้าคุณอยากให้ขึ้นใน authc ด้วย)
    if rest_l.startswith("enable"):
        if "succeed" in rest_l or "permitted" in rest_l:
            result = "ACCEPT"
        elif "fail" in rest_l or "deny" in rest_l or "denied" in rest_l:
            result = "REJECT"
        else:
            result = ""
        return _event(
            dt=dt,
            time_str=time_str,
            user=user,
            device=device,
            action="enable",
            result=result,
            raw=msg,
        )

    # logout (บางเครื่องอาจ log เป็น "logout ..." ในไฟล์ authc)
    if "logout" in rest_l:
        return _event(
            dt=dt,
            time_str=time_str,
            user=user,
            device=device,
            action="logout",
            result="OK",
            raw=msg,
        )

    return None



def _parse_acct(line: str) -> Optional[dict]:
    dt, time_str, msg = _split_ts(line)
    m = ACCT_RE.match(msg)
    if not m:
        return None

    device = m.group("device")
    user = m.group("user")
    op = m.group("op").lower()
    service = (m.group("service") or "").lower()
    cmd = (m.group("cmd") or "").strip()

    # เอาไว้โชว์ใน Authentication Logs ด้วย (action=acct_start/acct_stop)
    return _event(
        dt=dt,
        time_str=time_str,
        user=user,
        device=device,
        action=f"acct_{op}",
        result="OK",
        raw=msg,
        command=cmd if service == "shell" else "",
    )


def _parse_authz(line: str) -> Optional[dict]:
    dt, time_str, msg = _split_ts(line)
    m = AUTHZ_GENERIC_RE.match(msg)
    if not m:
        return None

    device = m.group("device")
    user = m.group("user")
    rest = (m.group("rest") or "").strip()

    # เดา result แบบง่าย ๆ (ถ้า log มีคำ permit/deny)
    rest_l = rest.lower()
    if any(x in rest_l for x in ["permit", "allow", "accept", "pass", "ok"]):
        result = "ACCEPT"
    elif any(x in rest_l for x in ["deny", "reject", "fail", "error"]):
        result = "REJECT"
    else:
        result = ""

    return _event(
        dt=dt,
        time_str=time_str,
        user=user,
        device=device,
        action="authz",
        result=result,
        raw=msg,
    )


# ---------- public API (ต้องมีให้ routes import ได้) ----------
def get_recent_events(
    limit: int = 200,
    *,
    start_dt: Optional[datetime] = None,
    end_dt: Optional[datetime] = None,
    user: str = "",
    device: str = "",
    result: str = "",
) -> list[dict]:
    """
    ใช้ในหน้า Logs & Audit (Authentication Logs table)
    รวม: authc + authz + acct + conn
    """
    # Prefer SQLite index if enabled (keeps .log as source of truth).
    if log_sqlite is not None and getattr(log_sqlite, "is_enabled", lambda: False)():
        try:
            log_sqlite.maybe_ingest_quick(
                parse_authc=_parse_authc,
                parse_authz=_parse_authz,
                parse_acct=_parse_acct,
                parse_conn=_parse_conn,
            )
            start_ts = start_dt.timestamp() if start_dt else None
            end_ts = end_dt.timestamp() if end_dt else None
            out = log_sqlite.query_recent_events(
                limit=int(limit),
                start_ts=start_ts,
                end_ts=end_ts,
                user=(user or ""),
                device=(device or ""),
                result=(result or ""),
            )
            if out:
                return out
        except Exception:
            # Fall back to file scan
            pass

    events: list[dict] = []

    if not LOG_DIR.exists():
        return []
    if start_dt and end_dt:
        authc_files = _files_for_range("authc-*.log", start_dt, end_dt)
        authz_files = _files_for_range("authz-*.log", start_dt, end_dt)
        acct_files = _files_for_range("acct-*.log", start_dt, end_dt)
        sources = [
            ("authc", authc_files, _parse_authc),
            ("authz", authz_files, _parse_authz),
            ("acct", acct_files, _parse_acct),
        ]
    else:
        sources = [
            ("authc", _latest_files("authc-*.log"), _parse_authc),
            ("authz", _latest_files("authz-*.log"), _parse_authz),
            ("acct", _latest_files("acct-*.log"), _parse_acct),
           # ("conn", _latest_files("conn-*.log"), _parse_conn),
        ]

    u = (user or "").strip()
    d = (device or "").strip()
    r = (result or "").strip()
    r_u = r.upper() if r else ""

    for _, files, parser in sources:
        for line in _read_recent_lines(files, max_lines_each=3000):
            e = parser(line)
            if not e:
                continue
            if u and (e.get("user") or "") != u:
                continue
            if d and (e.get("device") or "") != d:
                continue
            if r_u and (e.get("result") or "").upper() != r_u:
                continue
            events.append(e)

    if start_dt and end_dt:
        start_ts = start_dt.timestamp()
        end_ts = end_dt.timestamp()
        events = [e for e in events if float(e.get('_ts') or 0.0) >= start_ts and float(e.get('_ts') or 0.0) < end_ts]

    events.sort(key=lambda x: x.get("_ts", 0.0), reverse=True)
    out = events[: max(0, int(limit))]
    for e in out:
        e.pop("_ts", None)
    return out


def get_command_events(
    limit: int = 200,
    *,
    scan_all: bool = False,
    start_dt: Optional[datetime] = None,
    end_dt: Optional[datetime] = None,
    max_files: int = 4,
    max_lines_each: int = 6000,
    user: str = "",
    device: str = "",
    contains: str = "",
) -> list[dict]:
    """Return command audit events parsed from acct logs.

    Default behavior (fast):
      - read only latest `max_files` acct-*.log (newest first)
      - tail `max_lines_each` lines per file
      - return at most `limit` events

    If scan_all=True (historical search):
      - scan ALL acct-*.log files that still exist in LOG_DIR
      - read ALL lines per file (no tail)
      - apply optional filters (user/device/contains) while scanning
      - return at most `limit` events (sorted newest first)
    """

    # Prefer SQLite index if enabled (fast for historical search)
    if log_sqlite is not None and getattr(log_sqlite, "is_enabled", lambda: False)():
        try:
            log_sqlite.maybe_ingest_quick(
                parse_authc=_parse_authc,
                parse_authz=_parse_authz,
                parse_acct=_parse_acct,
                parse_conn=_parse_conn,
            )
            start_ts = start_dt.timestamp() if start_dt else None
            end_ts = end_dt.timestamp() if end_dt else None
            out = log_sqlite.query_command_events(
                limit=int(limit),
                user=(user or ""),
                device=(device or ""),
                contains=(contains or ""),
                start_ts=start_ts,
                end_ts=end_ts,
            )
            if out:
                return out
        except Exception:
            pass

    u = (user or "").strip()
    d = (device or "").strip()
    needle = (contains or "").strip().lower()

    # Keep only the newest `limit` events to cap memory even when scan_all=True.
    heap: list[tuple[float, int, dict]] = []
    seq = 0
    if start_dt and end_dt:
        files = _files_for_range("acct-*.log", start_dt, end_dt)
        per_file_lines = 0
    else:
        files = _all_files("acct-*.log") if scan_all else _latest_files("acct-*.log", max_files=max_files)
        per_file_lines = 0 if scan_all else max_lines_each

    for line in _read_recent_lines(files, max_lines_each=per_file_lines):
        e = _parse_acct(line)
        if not e:
            continue

        cmd = (e.get("command") or "").strip()
        if not cmd:
            continue

        # apply filters early (helps when scan_all=True)
        if u and (e.get("user") or "") != u:
            continue
        if d and (e.get("device") or "") != d:
            continue
        if needle:
            hay = (cmd or "")
            if needle not in hay.lower():
                # fallback to raw if needed
                raw = (e.get("raw") or "")
                if needle not in raw.lower():
                    continue

        e["action"] = "command"

        ts = float(e.get("_ts") or 0.0)
        if start_dt and end_dt:
            start_ts = start_dt.timestamp()
            end_ts = end_dt.timestamp()
            if ts <= 0.0 or ts < start_ts or ts >= end_ts:
                continue
        seq += 1
        item = (ts, seq, e)

        # bounded "top-N" heap by timestamp
        if int(limit) <= 0:
            continue
        if len(heap) < int(limit):
            heapq.heappush(heap, item)
        else:
            if ts > heap[0][0]:
                heapq.heapreplace(heap, item)

    # Sort newest first
    out = [it[2] for it in sorted(heap, key=lambda x: x[0], reverse=True)]
    for e in out:
        e.pop("_ts", None)
    return out


def get_user_stats() -> list[dict]:
    """
    สรุปง่าย ๆ ต่อ user (ใช้ใน card/ตารางสรุป)
    """
    events = get_recent_events(limit=2000)
    c = Counter(e.get("user") for e in events if e.get("user"))
    return [{"user": u, "count": n} for u, n in c.most_common()]

def get_last_login_map(
    *,
    max_files: int = 4,
    max_lines_each: int = 8000,
    successful_only: bool = True,
) -> dict[str, str]:
    """
    คืนค่า dict: { username: "YYYY-MM-DD HH:MM:SS +0700" }
    ดึงจาก authc-*.log โดยดู action=login
    - successful_only=True: เอาเฉพาะ ACCEPT
    """
    # Prefer SQLite index if enabled
    if log_sqlite is not None and getattr(log_sqlite, "is_enabled", lambda: False)():
        try:
            log_sqlite.maybe_ingest_quick(
                parse_authc=_parse_authc,
                parse_authz=_parse_authz,
                parse_acct=_parse_acct,
                parse_conn=_parse_conn,
            )
            out = log_sqlite.query_last_login_map(successful_only=bool(successful_only))
            if out:
                return out
        except Exception:
            pass

    last_time_by_user: dict[str, str] = {}
    last_ts_by_user: dict[str, float] = {}

    if not LOG_DIR.exists():
        return {}

    files = _latest_files("authc-*.log", max_files=max_files)
    for line in _read_recent_lines(files, max_lines_each=max_lines_each):
        e = _parse_authc(line)
        if not e:
            continue
        if (e.get("action") or "").lower() != "login":
            continue

        user = (e.get("user") or "").strip()
        if not user:
            continue

        res = (e.get("result") or "").upper()
        if successful_only and res not in ("ACCEPT", "OK", "SUCCESS", "PASS"):
            continue

        ts = float(e.get("_ts") or 0.0)
        if ts >= float(last_ts_by_user.get(user, -1.0)):
            last_ts_by_user[user] = ts
            last_time_by_user[user] = (e.get("time") or e.get("timestamp") or "").strip()

    return last_time_by_user


def get_summary() -> dict:
    """
    ใช้ใน dashboard.py (กัน ImportError)
    """
    events = get_recent_events(limit=2000)
    cmd_events = get_command_events(limit=2000)

    users = {e.get("user") for e in events if e.get("user")}
    devices = {e.get("device") for e in events if e.get("device")}

    success = sum(1 for e in events if (e.get("result") or "").upper() in ("ACCEPT", "OK", "PASS", "SUCCESS"))
    fail = sum(1 for e in events if (e.get("result") or "").upper() in ("REJECT", "FAIL", "ERROR"))

    return {
        "auth_events": len(events),
        "command_logs": len(cmd_events),
        "success": success,
        "failed": fail,
        "users": len(users),
        "devices": len(devices),
    }


def get_all_events(limit: int = 5000) -> list[dict]:
    """
    ใช้ใน api.py (กัน ImportError)
    """
    return get_recent_events(limit=limit)


