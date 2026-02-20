# tacacs_dashboard/services/web_terminal.py
from __future__ import annotations

import json
import os
import re
import socket
import socketserver
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

# In-memory sessions.
#
# IMPORTANT (multi-worker gunicorn):
# - A telnet session (pexpect child) cannot be shared across processes.
# - If gunicorn runs multiple workers, /terminal/send may hit a different worker
#   than /terminal/connect, causing "session not found".
#
# To make Web Terminal reliable across multiple workers, we run a lightweight
# in-process broker (single Unix socket server) in exactly one worker. All
# workers forward terminal requests to that broker.
#
# You can disable the broker and use plain in-memory sessions by setting:
#   WEB_TERMINAL_BROKER=0
_SESSIONS: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.RLock()

# Session idle timeout (seconds)
IDLE_TTL = 15 * 60  # 15 minutes


# -------------------------
# Broker (Unix socket)
# -------------------------
_BROKER_ENABLED = (os.getenv("WEB_TERMINAL_BROKER", "1") or "1").strip() not in ("0", "false", "False")
_BROKER_SOCK = (os.getenv("WEB_TERMINAL_BROKER_SOCK", "/tmp/tacacs_web_terminal.sock") or "/tmp/tacacs_web_terminal.sock").strip()
_BROKER_LOCK = (os.getenv("WEB_TERMINAL_BROKER_LOCK", "/tmp/tacacs_web_terminal.lock") or "/tmp/tacacs_web_terminal.lock").strip()

_BROKER_STARTED = False
_BROKER_START_LOCK = threading.Lock()
_BROKER_LOCK_FD = None  # keep fd open to hold flock


def _readline(sock: socket.socket, max_bytes: int = 2_000_000) -> bytes:
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if buf.endswith(b"\n"):
            break
        if len(buf) > max_bytes:
            raise RuntimeError("broker response too large")
    return bytes(buf)


def _broker_request(payload: Dict[str, Any], *, timeout_s: float = 6.0) -> Dict[str, Any]:
    """Send one request to broker and return response dict."""
    _ensure_broker()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    try:
        s.connect(_BROKER_SOCK)
        s.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
        raw = _readline(s)
        if not raw:
            return {"ok": False, "error": "empty response from broker"}
        return json.loads(raw.decode("utf-8", errors="replace"))
    finally:
        try:
            s.close()
        except Exception:
            pass


def _try_connect_broker() -> bool:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(0.25)
        s.connect(_BROKER_SOCK)
        s.sendall(b"{\"op\":\"ping\"}\n")
        _readline(s)
        s.close()
        return True
    except Exception:
        return False


def _ensure_broker() -> None:
    """Ensure a single broker server exists for this host.

    If we can acquire the broker lock, we start the server thread in this process.
    Otherwise, we wait until the socket becomes available.
    """
    if not _BROKER_ENABLED:
        return

    # Fast path: already connectable
    if _try_connect_broker():
        return

    global _BROKER_STARTED, _BROKER_LOCK_FD
    with _BROKER_START_LOCK:
        if _BROKER_STARTED:
            # started in this process, give it a moment
            for _ in range(30):
                if _try_connect_broker():
                    return
                time.sleep(0.05)
            return

        # Attempt to become broker owner via flock
        try:
            import fcntl  # Linux only (Ubuntu 22.04 OK)
            fd = os.open(_BROKER_LOCK, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                _BROKER_LOCK_FD = fd
            except Exception:
                os.close(fd)
                _BROKER_LOCK_FD = None
        except Exception:
            _BROKER_LOCK_FD = None

        if _BROKER_LOCK_FD is not None:
            # We are the broker owner. Clean stale socket and start server.
            try:
                if os.path.exists(_BROKER_SOCK):
                    try:
                        os.unlink(_BROKER_SOCK)
                    except Exception:
                        pass
            except Exception:
                pass

            _start_broker_server_thread()
            _BROKER_STARTED = True

        # Wait until broker becomes available (either our own or another worker)
        for _ in range(60):
            if _try_connect_broker():
                return
            time.sleep(0.05)


class _BrokerHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            line = self.rfile.readline(2_000_000)
            if not line:
                return
            req = json.loads(line.decode("utf-8", errors="replace")) if line else {}
            op = (req.get("op") or "").strip()
            if op == "ping":
                self.wfile.write(b"{\"ok\":true}\n")
                return

            if op == "create":
                sid, role, device_ip, level, output = _create_session_local(
                    req.get("device") or "",
                    req.get("username") or "",
                    req.get("password") or "",
                    timeout=int(req.get("timeout") or 10),
                )
                resp = {
                    "ok": True,
                    "session_id": sid,
                    "device_ip": device_ip,
                    "role": role,
                    "enable_level": level,
                    "output": output,
                }
                self.wfile.write((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
                return

            if op == "send":
                out = _send_line_local(req.get("session_id") or "", req.get("line") or "")
                resp = {"ok": True, "output": out}
                self.wfile.write((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
                return

            if op == "close":
                _close_session_local(req.get("session_id") or "")
                self.wfile.write(b"{\"ok\":true}\n")
                return

            self.wfile.write(b"{\"ok\":false,\"error\":\"unknown op\"}\n")
        except Exception as e:
            resp = {"ok": False, "error": str(e)}
            try:
                self.wfile.write((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
            except Exception:
                pass


class _ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def _start_broker_server_thread() -> None:
    # Restrict socket permissions (owner only)
    old_umask = os.umask(0o177)
    try:
        server = _ThreadingUnixServer(_BROKER_SOCK, _BrokerHandler)
    finally:
        os.umask(old_umask)

    t = threading.Thread(target=server.serve_forever, name="web-terminal-broker", daemon=True)
    t.start()


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
    if _BROKER_ENABLED:
        resp = _broker_request({
            "op": "create",
            "device": device,
            "username": username,
            "password": password,
            "timeout": int(timeout or 10),
        })
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error") or "broker create failed")
        return (
            resp.get("session_id") or "",
            resp.get("role") or "",
            resp.get("device_ip") or "",
            int(resp.get("enable_level") or 0),
            resp.get("output") or "",
        )
    return _create_session_local(device, username, password, timeout=timeout)


def send_line(session_id: str, line: str, *, timeout: int = 10) -> str:
    """Send a command (or control) to an existing session and return output."""
    if _BROKER_ENABLED:
        resp = _broker_request({
            "op": "send",
            "session_id": session_id,
            "line": line,
        }, timeout_s=max(2.0, float(timeout or 10)))
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error") or "broker send failed")
        return resp.get("output") or ""
    return _send_line_local(session_id, line, timeout=timeout)


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
    if _BROKER_ENABLED:
        resp = _broker_request({"op": "close", "session_id": session_id}, timeout_s=4.0)
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error") or "broker close failed")
        return
    with _LOCK:
        _close_nolock(session_id)


# -------------------------
# Local (broker-owned) impl
# -------------------------

def _create_session_local(
    device: str,
    username: str,
    password: str,
    *,
    timeout: int = 10,
) -> Tuple[str, str, str, int, str]:
    """Create session in the broker process."""
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
            "io_lock": threading.Lock(),
        }

    return sid, role, device_ip, level, _strip_ansi(output)


def _send_line_local(session_id: str, line: str, *, timeout: int = 10) -> str:
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
        io_lock: threading.Lock = s.get("io_lock") or threading.Lock()
        s["io_lock"] = io_lock

    if line is None:
        line = ""
    line = str(line)

    out = ""
    with io_lock:
        # Allow raw control like \x03 etc. If user passes "\\x03" string, convert.
        if line.startswith("\\x") and len(line) == 4:
            try:
                child.send(bytes([int(line[2:], 16)]).decode("latin1"))
            except Exception:
                child.send(line)
        else:
            child.sendline(line)

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


def _close_session_local(session_id: str) -> None:
    with _LOCK:
        _close_nolock(session_id)

