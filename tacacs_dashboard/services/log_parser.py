import os
from collections import defaultdict
from datetime import datetime

# Use example logs first
LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "sample_tacacs.log")
# After having real logs from tac_plus-ng, change to:
# LOG_PATH = "/var/log/tac_plus-ng.acct"


def parse_line(line: str):
    line = line.strip()
    if not line:
        return None

    parts = line.split()
    if len(parts) < 2:
        return None

    time_str = parts[0]
    data = {
        "time": time_str,
        "user": "",
        "role": "",
        "device": "",
        "action": "",
        "result": "",
    }

    # parse key=value from the rest
    for token in parts[1:]:
        # handle action that has space for example; action="command: ont reset 1 1"
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        # Cut " if there are any
        value = value.strip('"')
        if key in data:
            data[key] = value

    return data


def get_all_events():
    """read log from the file and give back list of event dict (old→new)"""
    events = []
    if not os.path.exists(LOG_PATH):
        return events

    with open(LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            ev = parse_line(line)
            if ev:
                events.append(ev)
    return events


def get_recent_events(limit: int = 20):
    """Give back list of the newest event limit list"""
    events = get_all_events()
    if not events:
        return []
    return events[-limit:]


def get_summary():
    """Calculate conclusion to use on Dashboard"""
    events = get_all_events()
    if not events:
        return {
            "active_users": 0,
            "failed_logins": 0,
            "devices": 0,
            "roles": 0,
        }

    # Count users who login success today (Easy way; all event that result=success)
    success_users = {e["user"] for e in events if e.get("result") == "success" and e.get("user")}
    active_users = len(success_users)

    # Count failed login
    failed_logins = sum(
        1
        for e in events
        if e.get("result") == "failed" and e.get("action", "").startswith("login")
    )

    # Count device
    devices = {e["device"] for e in events if e.get("device")}
    # Count role (Cut empty role and "-")
    roles = {e["role"] for e in events if e.get("role") and e.get("role") != "-"}

    return {
        "active_users": active_users,
        "failed_logins": failed_logins,
        "devices": len(devices),
        "roles": len(roles),
    }

def _normalize_timestamp(ts: str | None) -> datetime | None:
    """แปลง timestamp string เป็น datetime ถ้าทำได้"""
    if not ts:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def get_user_stats():
    """
    สรุปจำนวนการเข้าของทุก user จาก events ทั้งหมด
    คืนค่าเป็น list ของ dict:
    [
      {
        "user": "eng_bkk",
        "total": 10,
        "success": 9,
        "fail": 1,
        "last_seen": "2025-12-15 09:12:01"
      },
      ...
    ]
    """
    events = get_all_events()
    stats = defaultdict(lambda: {
        "user": "",
        "total": 0,
        "success": 0,
        "fail": 0,
        "last_seen": None,
    })

    for ev in events:
        user = ev.get("user") or ev.get("username") or "unknown"
        ts = ev.get("timestamp") or ev.get("time")
        event_type = (ev.get("event_type") or ev.get("type") or ev.get("event") or "").lower()
        result = (ev.get("result") or ev.get("status") or "").lower()

        # นับทุก event ที่มี user (ทั้ง login success/fail, command, etc.)
        s = stats[user]
        s["user"] = user
        s["total"] += 1

        if result in ("ok", "success", "pass", "accepted"):
            s["success"] += 1
        elif result in ("fail", "failed", "error", "denied"):
            s["fail"] += 1

        dt = _normalize_timestamp(ts)
        if dt:
            if s["last_seen"] is None or dt > s["last_seen"]:
                s["last_seen"] = dt

    # แปลง last_seen กลับเป็น string
    result_list = []
    for u, info in stats.items():
        last_seen_str = info["last_seen"].strftime("%Y-%m-%d %H:%M:%S") if info["last_seen"] else "-"
        result_list.append({
            "user": info["user"],
            "total": info["total"],
            "success": info["success"],
            "fail": info["fail"],
            "last_seen": last_seen_str,
        })

    # เรียงตาม total มาก → น้อย
    result_list.sort(key=lambda x: x["total"], reverse=True)
    return result_list


def get_command_events(limit: int = 200):
    """
    ดึงเฉพาะ event ที่เกี่ยวกับ 'command' (Accounting)
    เช่น มี field 'command' หรือ type=command
    """
    events = get_all_events()

    cmd_events: list[dict] = []
    for ev in events:
        event_type = (ev.get("event_type") or ev.get("type") or ev.get("event") or "").lower()
        has_cmd = "command" in ev or "cmd" in ev

        if event_type in ("command", "cmd") or has_cmd:
            cmd_events.append(ev)

    # เรียงตามเวลาใหม่ล่าสุดก่อน (ถ้ามี timestamp)
    def sort_key(ev):
        dt = _normalize_timestamp(ev.get("timestamp") or ev.get("time"))
        # ถ้า parse ไม่ได้ให้ใช้ year 1900 เพื่อให้ไปท้ายสุด
        return dt or datetime(1900, 1, 1)

    cmd_events.sort(key=sort_key, reverse=True)

    if limit and limit > 0:
        cmd_events = cmd_events[:limit]

    return cmd_events
