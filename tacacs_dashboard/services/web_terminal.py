# tacacs_dashboard/services/web_terminal.py
from __future__ import annotations

import re
import time
import uuid
import threading
from typing import Dict, Any, Optional, Tuple

import pexpect

from .policy_store import load_policy

# ZTE prompt: '>' (user exec) / '#' (privileged exec)
PROMPT_RE = re.compile(r"[>#]\s*$", re.M)
PASS_RE = re.compile(r"(?i)password:")
LOGIN_RE = re.compile(r"(?i)(username:|login:)")
DENIED_RE = re.compile(r"(?i)(denied|failed|not authorized|invalid|incorrect|authentication failed|login incorrect)")
MORE_RE = re.compile(r"--More--")

# In-memory sessions (⚠️ works reliably only with a single gunicorn worker, or sticky sessions)
_SESSIONS: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.RLock()

# Session idle timeout (seconds)
IDLE_TTL = 15 * 60  # 15 minutes


def _cleanup_expired() -> None:
    now = time.time()
    expired = []
    with _LOCK:
        for sid, s in _SESSIONS.items():
            if now - float(s.get("last_access", now)) > IDLE_TTL:
                expired.append(sid)
        for sid in expired:
            _close_nolock(sid)


def _device_ip_from_policy(device_name_or_ip: str) -> str:
    target = (device_name_or_ip or "").strip()
    if not target:
        raise ValueError("Device is required")

    # if looks like an IP, accept directly
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        return target

    policy = load_policy()
    for d in policy.get("devices", []):
        if (d.get("name") or "").strip() == target:
            ip = (d.get("ip") or "").strip()
            if ip:
                return ip
    raise ValueError("Device not found in policy.json")


def _role_for_user(username: str) -> str:
    policy = load_policy()
    for u in policy.get("users", []):
        if (u.get("username") or "").strip().lower() == username.strip().lower():
            return (u.get("roles") or "").strip()
    raise ValueError("User not found in policy.json (add user in dashboard first)")


def _enable_level_for_role(role: str) -> int:
    role = (role or "").strip().upper()
    policy = load_policy()
    for r in policy.get("roles", []):
        if (r.get("name") or "").strip().upper() == role:
            try:
                return int(str(r.get("privilege", "15")).strip())
            except Exception:
                return 15
    # fallback
    if role == "OLT_VIEW":
        return 1
    if role == "OLT_ENGINEER":
        return 7
    return 15


def _read_nonblocking(child: pexpect.spawn, budget_s: float = 0.25, chunk_size: int = 4096) -> str:
    """Read output for a short time window without blocking."""
    end = time.time() + budget_s
    out = []
    while time.time() < end:
        try:
            data = child.read_nonblocking(size=chunk_size, timeout=0.05)
            if data:
                out.append(data)
                # Auto-handle --More--
                if "--More--" in data:
                    child.send(" ")
                    continue
            else:
                break
        except pexpect.TIMEOUT:
            break
        except pexpect.EOF:
            break
    return "".join(out)


def create_session(
    device: str,
    username: str,
    password: str,
    *,
    timeout: int = 10,
) -> Tuple[str, str, str, int]:
    """
    Create interactive telnet session and auto-enable according to user's role.
    Returns: (session_id, role, device_ip, enable_level)
    """
    _cleanup_expired()

    username = (username or "").strip()
    if not username:
        raise ValueError("username required")

    device_ip = _device_ip_from_policy(device)
    role = _role_for_user(username)
    level = _enable_level_for_role(role)

    child = pexpect.spawn("telnet", [device_ip], encoding="utf-8", timeout=timeout)
    child.delaybeforesend = 0.05

    # Login
    child.expect([LOGIN_RE, pexpect.TIMEOUT])
    child.sendline(username)

    child.expect([PASS_RE, pexpect.TIMEOUT])
    child.sendline(password)

    # Wait for prompt or denied
    idx = child.expect([PROMPT_RE, DENIED_RE, pexpect.TIMEOUT], timeout=timeout)
    output = (child.before or "") + (child.after or "")
    if idx != 0:
        try:
            child.close(force=True)
        except Exception:
            pass
        raise RuntimeError("Login failed/denied/timeout")

    # Auto enable to role's level (if we're at '>')
    if (child.after or "").strip().endswith(">"):
        child.sendline(f"enable {level}")
        idx2 = child.expect([PASS_RE, PROMPT_RE, DENIED_RE, pexpect.TIMEOUT], timeout=timeout)
        output += (child.before or "") + (child.after or "")

        if idx2 == 0:  # Password:
            # enable <level> = login (send login password)
            child.sendline(password)
            idx3 = child.expect([PROMPT_RE, DENIED_RE, pexpect.TIMEOUT], timeout=timeout)
            output += (child.before or "") + (child.after or "")
            if idx3 != 0:
                child.close(force=True)
                raise RuntimeError("Enable failed (wrong password/denied/timeout)")
        elif idx2 == 2:
            child.close(force=True)
            raise RuntimeError("Enable denied")
        elif idx2 == 3:
            child.close(force=True)
            raise RuntimeError("Enable timeout")

    # Read any remaining data quickly
    output += _read_nonblocking(child, budget_s=0.2)

    sid = uuid.uuid4().hex
    with _LOCK:
        _SESSIONS[sid] = {
            "child": child,
            "device_ip": device_ip,
            "username": username,
            "role": role,
            "enable_level": level,
            "created": time.time(),
            "last_access": time.time(),
        }
    return sid, role, device_ip, level, output


def send_line(session_id: str, line: str, *, timeout: int = 10) -> str:
    _cleanup_expired()
    sid = (session_id or "").strip()
    if not sid:
        raise ValueError("session_id required")

    with _LOCK:
        s = _SESSIONS.get(sid)
        if not s:
            raise KeyError("session not found")
        s["last_access"] = time.time()
        child: pexpect.spawn = s["child"]

    # Send line
    # Allow raw control like \x03 etc. If user passes "\x03" string, convert.
    if line is None:
        line = ""
    line = str(line)
    if line.startswith("\\x") and len(line) == 4:
        try:
            child.send(bytes([int(line[2:], 16)]).decode("latin1"))
        except Exception:
            child.send(line)
    else:
        child.sendline(line)

    # Wait a bit for prompt or more output
    out = ""
    try:
        idx = child.expect([PROMPT_RE, MORE_RE, pexpect.TIMEOUT], timeout=0.5)
        out += (child.before or "") + (child.after or "")
        if idx == 1:
            # page more
            child.send(" ")
            out += _read_nonblocking(child, budget_s=0.4)
        else:
            out += _read_nonblocking(child, budget_s=0.2)
    except Exception:
        out += _read_nonblocking(child, budget_s=0.2)
    return out


def _close_nolock(session_id: str) -> None:
    s = _SESSIONS.pop(session_id, None)
    if not s:
        return
    child = s.get("child")
    try:
        if child is not None:
            child.close(force=True)
    except Exception:
        pass


def close_session(session_id: str) -> None:
    with _LOCK:
        _close_nolock(session_id)
