# tacacs_dashboard/services/web_terminal.py
from __future__ import annotations

import re
import time
import uuid
import threading
from typing import Dict, Any, Tuple
from pathlib import Path

import pexpect

from .policy_store import load_policy

# ZTE prompt: '>' (user exec) / '#' (privileged exec)
PROMPT_RE = re.compile(r"[>#]\s*$", re.M)
PASS_RE = re.compile(r"(?i)password:")
LOGIN_RE = re.compile(r"(?i)(username:|login:)")
DENIED_RE = re.compile(
    r"(?i)(denied|failed|not authorized|invalid|incorrect|authentication failed|login incorrect)"
)
MORE_RE = re.compile(r"--More--")

# In-memory sessions (works reliably with single gunicorn worker, or sticky sessions)
_SESSIONS: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.RLock()

# Session idle timeout (seconds)
IDLE_TTL = 15 * 60  # 15 minutes

# Project base dir (policy.json, secret.env อยู่ตรงนี้)
BASE_DIR = Path(__file__).resolve().parent.parent.parent
SECRET_ENV_PATH = BASE_DIR / "secret.env"


def _read_env(key: str, default: str = "") -> str:
    if not SECRET_ENV_PATH.exists():
        return default
    for line in SECRET_ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return default


def _cap(child: pexpect.spawn) -> str:
    """Capture child.before/after safely (after can be TIMEOUT/EOF objects)."""
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
    end = time.time() + budget_s
    out = []
    while time.time() < end:
        try:
            data = child.read_nonblocking(size=chunk_size, timeout=0.05)
            if data:
                out.append(data)
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


def _enable_with_fallbacks(
    child: pexpect.spawn,
    *,
    username: str,
    login_password: str,
    level: int,
    timeout: int,
) -> str:
    """
    Try enable with:
      1) login password
      2) enable password from secret.env (TACACS_ENABLE_PASSWORD / OLT_ENABLE15_PASSWORD)
      3) augmented format: "username password"  (for $enab..$ style clients) 
    Returns captured output.
    """
    out = ""

    child.sendline(f"enable {level}")
    idx = child.expect([PASS_RE, PROMPT_RE, DENIED_RE, pexpect.TIMEOUT], timeout=timeout)
    out += _cap(child)

    if idx == 1:
        return out  # no password asked, already at prompt
    if idx == 2:
        raise RuntimeError("Enable denied\n" + out)
    if idx == 3:
        raise RuntimeError("Enable timeout\n" + out)

    # idx == 0 -> password prompt
    enable_pw = _read_env("TACACS_ENABLE_PASSWORD", "") or _read_env("OLT_ENABLE15_PASSWORD", "")
    candidates = [login_password]
    if enable_pw and enable_pw not in candidates:
        candidates.append(enable_pw)
    augmented = f"{username} {login_password}"
    if augmented not in candidates:
        candidates.append(augmented)

    for cand in candidates:
        child.sendline(cand)
        idx2 = child.expect([PROMPT_RE, PASS_RE, DENIED_RE, pexpect.TIMEOUT], timeout=timeout)
        out += _cap(child)

        if idx2 == 0:
            return out
        if idx2 == 1:
            # asked password again -> try next candidate
            continue
        if idx2 == 2:
            raise RuntimeError("Enable denied\n" + out)

    raise RuntimeError("Enable failed (wrong password/timeout)\n" + out)


def create_session(
    device: str,
    username: str,
    password: str,
    *,
    timeout: int = 10,
) -> Tuple[str, str, str, int, str]:
    """
    Create interactive telnet session and auto-enable according to user's role.
    Returns: (session_id, role, device_ip, enable_level, output)
    """
    _cleanup_expired()

    username = (username or "").strip()
    if not username:
        raise ValueError("username required")

    device_ip = _device_ip_from_policy(device)
    role = _role_for_user(username)
    level = _enable_level_for_role(role)

    child = pexpect.spawn("/usr/bin/telnet", [device_ip], encoding="utf-8", timeout=timeout)
    child.delaybeforesend = 0.05

    output = ""

    # Wait Username
    idx = child.expect([LOGIN_RE, DENIED_RE, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout * 2)
    output += _cap(child)
    if idx != 0:
        child.close(force=True)
        raise RuntimeError("Timeout/EOF waiting for Username prompt\n" + output)

    child.sendline(username)

    # Wait Password
    idx = child.expect([PASS_RE, DENIED_RE, LOGIN_RE, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout * 2)
    output += _cap(child)
    if idx != 0:
        child.close(force=True)
        raise RuntimeError("Timeout/EOF waiting for Password prompt\n" + output)

    child.sendline(password)

    # Wait prompt
    idx = child.expect([PROMPT_RE, DENIED_RE, LOGIN_RE, PASS_RE, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout * 3)
    output += _cap(child)

    if idx == 1:
        child.close(force=True)
        raise RuntimeError("Login denied\n" + output)
    if idx in (2, 3):
        child.close(force=True)
        raise RuntimeError("Login failed (got Username/Password again)\n" + output)
    if idx in (4, 5):
        child.close(force=True)
        raise RuntimeError("Timeout/EOF waiting for prompt after login\n" + output)

    # Auto enable to role's level (if we're at '>')
    if (child.after or "").strip().endswith(">"):
        try:
            output += _enable_with_fallbacks(
                child,
                username=username,
                login_password=password,
                level=level,
                timeout=timeout,
            )
        except Exception as e:
            child.close(force=True)
            raise

    # Grab any remaining output quickly
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

    if line is None:
        line = ""
    line = str(line)

    # allow raw control like "\x03"
    if line.startswith("\\x") and len(line) == 4:
        try:
            child.send(bytes([int(line[2:], 16)]).decode("latin1"))
        except Exception:
            child.send(line)
        return _read_nonblocking(child, budget_s=0.35)

    # ---- HELP MODE (?) ----
    is_help = line.rstrip().endswith("?")

    out = ""

    if is_help:
        # 1) ส่งแบบไม่กด Enter (ให้มันทำ inline help)
        child.send(line)

        # 2) อ่าน output help
        out += _read_nonblocking(child, budget_s=0.55)

        # 3) ล้างบรรทัดที่ค้างไว้ (เช่น "pon ")
        # Ctrl+U = clear line (ส่วนใหญ่ CLI network รองรับ)
        child.send("\x15")
        # redraw prompt ด้วย Enter เปล่า
        child.send("\r")

        # 4) รอ prompt กลับมา (ถ้าไม่มาก็ fallback ด้วย Ctrl+C)
        try:
            child.expect([PROMPT_RE, pexpect.TIMEOUT], timeout=0.8)
            out += _cap(child)
        except Exception:
            pass

        if not PROMPT_RE.search(out):
            # fallback: Ctrl+C แล้ว Enter
            child.send("\x03")
            child.send("\r")
            try:
                child.expect([PROMPT_RE, pexpect.TIMEOUT], timeout=0.8)
                out += _cap(child)
            except Exception:
                pass

        out += _read_nonblocking(child, budget_s=0.25)
        return out

    # ---- NORMAL COMMAND ----
    child.sendline(line)

    # อ่าน output แบบสั้น ๆ + page more
    out += _read_nonblocking(child, budget_s=0.35)

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

