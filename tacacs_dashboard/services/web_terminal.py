# tacacs_dashboard/services/web_terminal.py
from __future__ import annotations

import re
import time
import uuid
import threading
from typing import Dict, Any, Tuple

import pexpect

from .policy_store import load_policy
from .tacacs_config import _parse_privilege

# ZTE prompt: '>' (user exec) / '#' (privileged exec)
PROMPT_RE = re.compile(r"[>#]\s*$", re.M)
PASS_RE = re.compile(r"(?i)password:")
LOGIN_RE = re.compile(r"(?i)(username:|login:)")
DENIED_RE = re.compile(r"(?i)(denied|failed|not authorized|invalid|incorrect|authentication failed|login incorrect)")
MORE_RE = re.compile(r"--More--")

# In-memory sessions (⚠️ reliable only with a single gunicorn worker, or sticky sessions)
_SESSIONS: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.RLock()

# Session idle timeout (seconds)
IDLE_TTL = 15 * 60  # 15 minutes


def _cap(child: pexpect.spawn) -> str:
    """Capture child.before/after safely (after can be pexpect.TIMEOUT/EOF types)."""
    before = child.before or ""
    after = child.after if isinstance(child.after, str) else ""
    return before + after


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
            ip = (d.get("ip") or d.get("address") or "").strip()
            if ip:
                return ip
    raise ValueError("Device not found in policy.json")


def _role_for_user(username: str) -> str:
    policy = load_policy()
    for u in policy.get("users", []):
        if (u.get("username") or "").strip().lower() == username.strip().lower():
            return (u.get("roles") or u.get("role") or "").strip()
    raise ValueError("User not found in policy.json (add user in dashboard first)")


def _priv_level_for_role(role: str) -> int:
    """Return intended privilege from policy.roles. Fallback: VIEW=1, ENGINEER=7, else 15."""
    role = (role or "").strip()
    policy = load_policy()
    for r in policy.get("roles", []):
        if (r.get("name") or "").strip().upper() == role.upper():
            return _parse_privilege(r.get("privilege"))

    # fallback
    ru = role.upper()
    if ru == "OLT_VIEW":
        return 1
    if ru == "OLT_ENGINEER":
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


# --- ANSI / cursor-control cleanup ---
# (helps when user runs help like: `pon ?` which some CLIs print with cursor moves)
_ANSI_RE = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"  # CSI/ESC sequences
)
_CSI_MOVE_RE = re.compile(r"\x1B\[[0-9;]*[A-Za-z]")


def _strip_ansi(s: str) -> str:
    if not s:
        return ""
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = _ANSI_RE.sub("", s)
    s = _CSI_MOVE_RE.sub("", s)
    return s


def _normalize_backspaces(s: str) -> str:
    if not s:
        return ""
    buf: list[str] = []
    for ch in s:
        if ch == "\b":
            if buf:
                buf.pop()
        else:
            buf.append(ch)
    return "".join(buf)


def create_session(
    device: str,
    username: str,
    password: str,
    *,
    timeout: int = 10,
) -> Tuple[str, str, str, int, str]:
    """Create interactive telnet session.

    NOTE: We no longer auto-send `enable <level>` here.
    Your TACACS profile now sets privilege (priv-lvl) at login.

    Returns: (session_id, role, device_ip, privilege_level, output)
    """
    _cleanup_expired()

    username = (username or "").strip()
    if not username:
        raise ValueError("username required")

    device_ip = _device_ip_from_policy(device)
    role = _role_for_user(username)
    level = _priv_level_for_role(role)

    child = pexpect.spawn("/usr/bin/telnet", [device_ip], encoding="utf-8", timeout=timeout)
    child.delaybeforesend = 0.05

    output = ""

    # Wait for Username/Login prompt
    idx = child.expect([LOGIN_RE, PASS_RE, PROMPT_RE, DENIED_RE, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
    output += _cap(child)
    if idx == 4:
        child.close(force=True)
        raise RuntimeError("Timeout waiting for Username prompt")
    if idx == 5:
        child.close(force=True)
        raise RuntimeError("Connection closed (EOF) while waiting for login")
    if idx == 3:
        child.close(force=True)
        raise RuntimeError("Login denied")

    # If device asks for username
    if idx == 0:
        child.sendline(username)
        idx2 = child.expect([PASS_RE, DENIED_RE, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
        output += _cap(child)
        if idx2 == 1:
            child.close(force=True)
            raise RuntimeError("Login denied")
        if idx2 == 2:
            child.close(force=True)
            raise RuntimeError("Timeout waiting for Password prompt")
        if idx2 == 3:
            child.close(force=True)
            raise RuntimeError("Connection closed (EOF) while waiting for password")

    # If it was already at password prompt, continue
    child.sendline(password)

    # Wait for prompt after login
    idx3 = child.expect([PROMPT_RE, DENIED_RE, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout * 2)
    output += _cap(child)
    if idx3 == 1:
        child.close(force=True)
        raise RuntimeError("Login denied")
    if idx3 == 2:
        child.close(force=True)
        raise RuntimeError("Timeout waiting for prompt after login")
    if idx3 == 3:
        child.close(force=True)
        raise RuntimeError("Connection closed (EOF) after login")

    # Read any remaining data quickly
    output += _read_nonblocking(child, budget_s=0.2)

    sid = uuid.uuid4().hex
    with _LOCK:
        _SESSIONS[sid] = {
            "child": child,
            "device_ip": device_ip,
            "username": username,
            "role": role,
            "enable_level": level,  # kept for backwards compatibility with UI
            "created": time.time(),
            "last_access": time.time(),
        }

    return sid, role, device_ip, level, _strip_ansi(output)


def send_line(session_id: str, line: str, *, timeout: int = 10) -> str:
    """Send a command (or control) to an existing session and return output."""
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

    if line is None:
        line = ""
    line = str(line)

    # Allow raw control like \x03 etc. If user passes "\\x03" string, convert.
    if line.startswith("\\x") and len(line) == 4:
        try:
            child.send(bytes([int(line[2:], 16)]).decode("latin1"))
        except Exception:
            child.send(line)
    else:
        child.sendline(line)

    out = ""
    try:
        idx = child.expect([PROMPT_RE, MORE_RE, pexpect.TIMEOUT], timeout=0.6)
        out += _cap(child)
        if idx == 1:
            child.send(" ")
            out += _read_nonblocking(child, budget_s=0.4)
        else:
            out += _read_nonblocking(child, budget_s=0.2)
    except Exception:
        out += _read_nonblocking(child, budget_s=0.2)

    out = _normalize_backspaces(_strip_ansi(out))
    return out


def get_session_meta(session_id: str) -> Dict[str, Any]:
    sid = (session_id or "").strip()
    if not sid:
        raise ValueError("session_id required")

    with _LOCK:
        s = _SESSIONS.get(sid)
        if not s:
            raise KeyError("session not found")
        return {
            "device_ip": s.get("device_ip"),
            "username": s.get("username"),
            "role": s.get("role"),
            "enable_level": s.get("enable_level"),
            "created": s.get("created"),
            "last_access": s.get("last_access"),
        }


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

