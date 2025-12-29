# tacacs_dashboard/services/log_parser.py
from __future__ import annotations

from pathlib import Path
import re
from datetime import datetime, timezone
from collections import Counter
from typing import Optional, Iterable

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

    time_str = f"{ts} {tz}".strip()
    dt = None
    try:
        if tz:
            dt = datetime.strptime(f"{ts} {tz}", "%Y-%m-%d %H:%M:%S %z").astimezone(timezone.utc)
        else:
            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        dt = None

    return dt, time_str, msg


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
    for p in files:
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            if max_lines_each and len(lines) > max_lines_each:
                lines = lines[-max_lines_each:]
            for line in lines:
                if line.strip():
                    yield line
        except Exception:
            continue


def _latest_files(glob_pat: str, max_files: int = 4) -> list[Path]:
    files = sorted(LOG_DIR.glob(glob_pat), key=lambda x: x.stat().st_mtime, reverse=True)
    return files[:max_files]


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
            raw=line.strip(),
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
        raw=line.strip(),
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
        raw=line.strip(),
    )


# ---------- public API (ต้องมีให้ routes import ได้) ----------
def get_recent_events(limit: int = 200) -> list[dict]:
    """
    ใช้ในหน้า Logs & Audit (Authentication Logs table)
    รวม: authc + authz + acct + conn
    """
    events: list[dict] = []

    if not LOG_DIR.exists():
        return []

    sources = [
        ("authc", _latest_files("authc-*.log"), _parse_authc),
        ("authz", _latest_files("authz-*.log"), _parse_authz),
        ("acct", _latest_files("acct-*.log"), _parse_acct),
       # ("conn", _latest_files("conn-*.log"), _parse_conn),
    ]

    for _, files, parser in sources:
        for line in _read_recent_lines(files, max_lines_each=3000):
            e = parser(line)
            if e:
                events.append(e)

    events.sort(key=lambda x: x.get("_ts", 0.0), reverse=True)
    out = events[: max(0, int(limit))]
    for e in out:
        e.pop("_ts", None)
    return out


def get_command_events(limit: int = 200) -> list[dict]:
    """
    ใช้ในหน้า Logs & Audit (Command Logs table)
    ดึงจาก acct log เป็นหลัก (เพราะมี cmd ต่อท้าย)
    """
    cmds: list[dict] = []
    files = _latest_files("acct-*.log")
    for line in _read_recent_lines(files, max_lines_each=6000):
        e = _parse_acct(line)
        if not e:
            continue
        cmd = (e.get("command") or "").strip()
        if cmd:
            e["action"] = "command"
            cmds.append(e)

    cmds.sort(key=lambda x: x.get("_ts", 0.0), reverse=True)
    out = cmds[: max(0, int(limit))]
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

