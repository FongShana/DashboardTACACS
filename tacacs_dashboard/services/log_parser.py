import os

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
