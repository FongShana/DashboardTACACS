# tacacs_dashboard/services/log_parser.py
from __future__ import annotations

from collections import deque, defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path
import re
from typing import Iterable, Optional

LOG_DIR = Path("/var/log/tac_plus")

# ---------- regex ช่วย parse ----------
MONTH_RE = re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
ISO_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# username patterns ที่เจอบ่อยกับ tac_plus-ng
USER_RE_LIST = [
    re.compile(r"for\s+'([^']+)'", re.IGNORECASE),
    re.compile(r"login\s+for\s+\"([^\"]+)\"", re.IGNORECASE),
    re.compile(r"\buser(?:name)?[:=]\s*([A-Za-z0-9_.-]+)", re.IGNORECASE),
]

# command patterns ที่เจอบ่อย
CMD_RE_LIST = [
    re.compile(r"\bcmd\s*=\s*'([^']+)'", re.IGNORECASE),
    re.compile(r"\bcmd\s*=\s*\"([^\"]+)\"", re.IGNORECASE),
    re.compile(r"\bcommand\s+\"([^\"]+)\"", re.IGNORECASE),
    re.compile(r"\bcommand\s+'([^']+)'", re.IGNORECASE),
    re.compile(r"\bcmd\s+(.+)$", re.IGNORECASE),  # fallback
]


def _latest_files(prefix: str, take: int = 2) -> list[Path]:
    files = sorted(LOG_DIR.glob(f"{prefix}-*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:take]


def _tail_lines(path: Path, limit: int) -> list[str]:
    dq: deque[str] = deque(maxlen=limit)
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            dq.append(line.rstrip("\n"))
    return list(dq)


def _extract_ts(line: str) -> str:
    m = ISO_RE.match(line)
    if m:
        return m.group(1)
    m2 = MONTH_RE.match(line)
    if m2:
        # เก็บแบบ syslog สั้น ๆ ก็ยังช่วยเรียง/แสดงได้
        parts = line.split()
        return " ".join(parts[:3])  # Dec 23 07:55:46
    return ""


def _extract_user(line: str) -> str:
    for r in USER_RE_LIST:
        m = r.search(line)
        if m:
            return (m.group(1) or "").strip()
    return ""


def _extract_device_ip(line: str) -> str:
    ips = IP_RE.findall(line)
    # tac_plus-ng ส่วนใหญ่จะเริ่มด้วย device_ip
    return ips[0] if ips else ""


def _extract_src_ip(line: str) -> str:
    ips = IP_RE.findall(line)
    # บางบรรทัดมีทั้ง device_ip และ src_ip เช่น "from 10.x.x.x"
    # เลือกตัวสุดท้ายเป็น src แบบคร่าว ๆ
    return ips[-1] if len(ips) >= 2 else ""


def _guess_result(line: str) -> str:
    s = line.lower()
    if "succeed" in s or "accepted" in s or "success" in s or "permit" in s:
        return "ACCEPT"
    if "fail" in s or "reject" in s or "denied" in s or "error" in s:
        return "REJECT"
    return ""


def _guess_action(prefix: str, line: str) -> str:
    s = line.lower()
    if prefix == "authc":
        if "login" in s:
            return "login"
        return "authc"
    if prefix == "conn":
        if "disconnect" in s or "close" in s or "closed" in s or "logout" in s:
            return "logout"
        return "conn"
    if prefix == "authz":
        return "command"
    if prefix == "acct":
        # บาง vendor ส่ง command accounting มาใน acct
        if "cmd" in s or "command" in s:
            return "command"
        return "acct"
    return ""


def _extract_cmd(line: str) -> str:
    for r in CMD_RE_LIST:
        m = r.search(line)
        if m:
            return (m.group(1) or "").strip()
    return ""


def _parse_line(prefix: str, line: str) -> dict:
    ts = _extract_ts(line)
    device = _extract_device_ip(line)
    user = _extract_user(line)
    src = _extract_src_ip(line)
    result = _guess_result(line)
    action = _guess_action(prefix, line)

    evt = {
        "time": ts,
        "device": device,
        "src": src,
        "user": user,
        "result": result,
        "action": action,
        "raw": line,
    }

    if action == "command":
        evt["command"] = _extract_cmd(line)

    return evt


def _load_events_from_prefix(prefix: str, limit: int = 200) -> list[dict]:
    # อ่านไฟล์ล่าสุด 1–2 ไฟล์ เผื่อข้ามวัน/rotate
    files = _latest_files(prefix, take=2)
    if not files:
        return []

    # ดึงท้ายไฟล์รวมกัน
    lines: list[str] = []
    per_file = max(50, limit)  # กันไม่พอ
    for p in reversed(files):  # เก่าก่อนใหม่
        lines.extend(_tail_lines(p, per_file))

    # parse แล้วเอาเฉพาะท้าย ๆ limit
    events = [_parse_line(prefix, ln) for ln in lines if ln.strip()]
    return events[-limit:]


# ---------- API ที่ routes/logs.py เรียก ----------
def get_recent_events(limit: int = 200) -> list[dict]:
    """
    ใช้สำหรับตาราง auth (login/logout)
    """
    authc = _load_events_from_prefix("authc", limit=limit)
    conn = _load_events_from_prefix("conn", limit=limit)

    # รวมกันแล้วเรียงแบบ “แสดงใหม่ก่อน” ด้วย heuristic:
    merged = authc + conn
    # ถ้า time ว่าง จะคงท้าย ๆ ไว้ก่อน
    merged.sort(key=lambda e: (e.get("time") or ""), reverse=True)
    return merged[:limit]


def get_command_events(limit: int = 200) -> list[dict]:
    """
    ดึง command จาก authz + acct (บางเครื่องส่ง command ไป acct)
    """
    authz = _load_events_from_prefix("authz", limit=limit)
    acct = _load_events_from_prefix("acct", limit=limit)

    merged = []
    for e in (authz + acct):
        if e.get("action") == "command":
            merged.append(e)

    merged.sort(key=lambda e: (e.get("time") or ""), reverse=True)
    return merged[:limit]


def get_user_stats() -> list[dict]:
    """
    สรุป per-user (success/fail/last_seen) จาก auth events
    คืน list ของ dict เพื่อ render ง่าย
    """
    events = get_recent_events(limit=1000)
    stats = defaultdict(lambda: {"user": "", "success": 0, "fail": 0, "last_seen": ""})

    for e in events:
        user = e.get("user") or ""
        if not user:
            continue
        st = stats[user]
        st["user"] = user

        res = (e.get("result") or "").upper()
        if res in ("ACCEPT", "OK", "PASS", "SUCCESS"):
            st["success"] += 1
        elif res in ("REJECT", "FAIL", "ERROR"):
            st["fail"] += 1

        t = e.get("time") or ""
        if t and t > (st["last_seen"] or ""):
            st["last_seen"] = t

    # เรียงตาม last_seen ใหม่สุด
    return sorted(stats.values(), key=lambda x: x.get("last_seen") or "", reverse=True)

def get_summary():
    """
    ใช้บนหน้า dashboard: สรุปจำนวน event/login/cmd ล่าสุดแบบง่าย ๆ
    (ทำแบบ safe: ไม่มี log ก็ไม่พัง)
    """
    try:
        recent = get_recent_events(limit=200)
        cmds = get_command_events(limit=200)

        success = sum(
            1 for e in recent
            if (e.get("result") or "").upper() in ("ACCEPT", "OK", "PASS", "SUCCESS")
        )
        fail = sum(
            1 for e in recent
            if (e.get("result") or "").upper() in ("REJECT", "FAIL", "ERROR")
        )

        uniq_users = len({e.get("user") for e in recent if e.get("user")})
        uniq_devices = len({e.get("device") for e in recent if e.get("device")})

        return {
            "total_events": len(recent),
            "total_cmd": len(cmds),
            "success": success,
            "fail": fail,
            "unique_users": uniq_users,
            "unique_devices": uniq_devices,
        }
    except Exception:
        return {
            "total_events": 0,
            "total_cmd": 0,
            "success": 0,
            "fail": 0,
            "unique_users": 0,
            "unique_devices": 0,
        }

def get_all_events(limit=1000):
    """
    ใช้ให้ API เรียกเอา event ทั้งหมดแบบรวม ๆ
    คืนเป็น list ที่รวม auth events + command events
    """
    auth_events = get_recent_events(limit=limit) or []
    cmd_events = get_command_events(limit=limit) or []

    combined = []

    for e in auth_events:
        x = dict(e)
        x.setdefault("event_type", "auth")
        combined.append(x)

    for e in cmd_events:
        x = dict(e)
        x.setdefault("event_type", "cmd")
        combined.append(x)

    # ไม่บังคับ sort เพราะ format เวลาใน log อาจไม่เหมือนกัน
    return combined
