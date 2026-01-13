# tacacs_dashboard/services/olt_telnet.py
from __future__ import annotations

"""Reusable Telnet command runner for ZTE OLT (and similar CLIs).

Used by:
- olt_bootstrap.py (bootstrap AAA templates / binds)
- olt_provision.py (provision / deprovision users)

Key behaviors:
- Robust login flow (Username/login: or Password: directly)
- Send commands line-by-line and wait for prompt after each command
- Auto-handle "--More--" pagination
- Detect denied/auth failures/timeouts early and raise meaningful errors
- Return output in a readable "per-command" format (good for flashing in UI)

NOTE: Web Terminal has its own in-memory session implementation.
This module is for one-shot "connect -> run -> disconnect" jobs.
"""

import re
import shutil
import time
from dataclasses import dataclass
from typing import Optional, Any

import pexpect


# --- Prompt / message patterns (ZTE typical) ---
PROMPT_RE = re.compile(r"[>#]\s*$", re.M)  # user exec '>' / privileged '#'
LOGIN_RE = re.compile(r"(?i)(username:|login:)")
PASS_RE = re.compile(r"(?i)password:")
LOGIN_FAIL_RE = re.compile(r"(?i)(login incorrect|bad password|authentication failed)")
DENIED_RE = re.compile(r"(?i)(denied|not authorized|invalid|incorrect|failed)")
MORE_RE = re.compile(r"--More--")

# map role -> enable level
ROLE_TO_ENABLE = {"OLT_VIEW": 1, "OLT_ENGINEER": 7, "OLT_ADMIN": 15}

# ANSI / cursor-control cleanup (helps for help output like: `pon ?`)
_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
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


def _clean_output(s: str) -> str:
    s = _strip_ansi(s)
    s = _normalize_backspaces(s)
    # reduce excessive blank lines
    s = re.sub(r"\n{4,}", "\n\n\n", s)
    return s


def _cap(child: pexpect.spawn) -> str:
    """Capture child.before + child.after safely."""
    before = child.before or ""
    after = child.after if isinstance(child.after, str) else ""
    return before + after


def _telnet_bin() -> str:
    # Prefer absolute path (systemd often has limited PATH)
    for p in ("/usr/bin/telnet", "/bin/telnet"):
        try:
            if shutil.which(p) or (p and __import__("os").path.exists(p)):
                return p
        except Exception:
            pass
    return shutil.which("telnet") or "/usr/bin/telnet"


def _resolve_enable_level(role: Optional[str], enable_level: Optional[int]) -> int:
    if role:
        return int(ROLE_TO_ENABLE.get(role.strip().upper(), 15))
    if enable_level is not None:
        return int(enable_level)
    return 15


@dataclass
class TelnetCommandResult:
    cmd: str
    output: str


def _expect_one(
    child: pexpect.spawn,
    patterns: list[Any],
    out_chunks: list[str],
    *,
    timeout: int,
) -> int:
    idx = child.expect(patterns, timeout=timeout)
    out_chunks.append(_cap(child))
    return idx


def _login(
    child: pexpect.spawn,
    *,
    username: str,
    password: str,
    timeout: int,
    out_chunks: list[str],
) -> None:
    """Login and stop at a prompt."""
    username = (username or "").strip()
    if not username:
        raise ValueError("username is required")

    idx = _expect_one(
        child,
        [LOGIN_RE, PASS_RE, PROMPT_RE, DENIED_RE, pexpect.TIMEOUT, pexpect.EOF],
        out_chunks,
        timeout=timeout,
    )

    if idx == 3:
        raise RuntimeError("Login denied (device refused before credentials).")
    if idx == 4:
        raise TimeoutError("Timeout waiting for login prompt.")
    if idx == 5:
        raise RuntimeError("Connection closed (EOF) while waiting for login prompt.")

    if idx == 2:
        return

    if idx == 0:
        child.sendline(username)
        _expect_one(child, [PASS_RE, DENIED_RE, pexpect.TIMEOUT, pexpect.EOF], out_chunks, timeout=timeout)
        if DENIED_RE.search(out_chunks[-1]) if out_chunks else False:
            raise RuntimeError("Login denied after sending username.")

    child.sendline(password)

    idx2 = _expect_one(
        child,
        [PROMPT_RE, LOGIN_FAIL_RE, DENIED_RE, pexpect.TIMEOUT, pexpect.EOF],
        out_chunks,
        timeout=max(3, int(timeout) * 2),
    )
    if idx2 in (1, 2):
        raise RuntimeError("Login failed (bad username/password or denied).")
    if idx2 == 3:
        raise TimeoutError("Timeout waiting for prompt after login.")
    if idx2 == 4:
        raise RuntimeError("Connection closed (EOF) after login.")


def _auto_enable(
    child: pexpect.spawn,
    *,
    level: int,
    login_password: str,
    enable_password: Optional[str],
    timeout: int,
    out_chunks: list[str],
) -> None:
    """If currently at '>' prompt, send `enable <level>` and answer password if asked."""
    prompt = (child.after or "") if isinstance(child.after, str) else ""
    if not prompt.strip().endswith(">"):
        return

    child.sendline(f"enable {int(level)}")
    idx = _expect_one(
        child,
        [PASS_RE, PROMPT_RE, DENIED_RE, pexpect.TIMEOUT, pexpect.EOF],
        out_chunks,
        timeout=timeout,
    )
    if idx == 0:
        child.sendline((enable_password or "").strip() or (login_password or ""))
        idx2 = _expect_one(
            child,
            [PROMPT_RE, DENIED_RE, pexpect.TIMEOUT, pexpect.EOF],
            out_chunks,
            timeout=timeout,
        )
        if idx2 != 0:
            raise RuntimeError("Enable failed (password wrong/denied/timeout).")
    elif idx == 1:
        return
    elif idx == 2:
        raise RuntimeError("Enable denied by device.")
    elif idx == 3:
        raise TimeoutError("Enable timeout.")
    else:
        raise RuntimeError("Connection closed (EOF) during enable.")


def _run_one_command(
    child: pexpect.spawn,
    *,
    cmd: str,
    timeout: int,
    out_chunks: list[str],
) -> str:
    """Send one command and read until prompt. Returns raw output for this command."""
    child.sendline(cmd)
    buf: list[str] = []

    while True:
        idx = child.expect([MORE_RE, PROMPT_RE, DENIED_RE, LOGIN_FAIL_RE, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
        piece = _cap(child)
        out_chunks.append(piece)
        buf.append(piece)

        if idx == 0:
            child.send(" ")
            time.sleep(0.05)
            continue
        if idx == 1:
            break
        if idx in (2, 3):
            raise RuntimeError(f"Command denied/failed: {cmd}")
        if idx == 4:
            raise TimeoutError(f"Timeout waiting for prompt after command: {cmd}")
        break

    return "".join(buf)


def telnet_exec_commands(
    host: str,
    *,
    commands: list[str],
    timeout: int = 10,
    # credentials (accept both naming styles)
    username: Optional[str] = None,
    password: Optional[str] = None,
    enable_password: Optional[str] = None,
    admin_user: Optional[str] = None,
    admin_pass: Optional[str] = None,
    enable_pass: Optional[str] = None,
    # privilege / enable behavior
    role: Optional[str] = None,
    enable_level: Optional[int] = None,
    auto_enable: bool = True,
    # output behavior
    debug: bool = False,
    max_output_chars: int = 12000,
) -> str:
    """Connect via telnet, login, (optionally) enable, run commands, disconnect."""
    host = (host or "").strip()
    if not host:
        raise ValueError("host is required")

    user = (username if username is not None else admin_user) or ""
    pw = (password if password is not None else admin_pass) or ""
    en_pw = (enable_password if enable_password is not None else enable_pass)

    if not user.strip():
        raise ValueError("username/admin_user is required")
    if pw is None:
        pw = ""

    telnet_bin = _telnet_bin()
    child = pexpect.spawn(telnet_bin, [host], encoding="utf-8", timeout=timeout)
    child.delaybeforesend = 0.05

    out_chunks: list[str] = []
    per_cmd: list[TelnetCommandResult] = []

    try:
        _login(child, username=user, password=pw, timeout=timeout, out_chunks=out_chunks)

        if auto_enable:
            lvl = _resolve_enable_level(role, enable_level)
            _auto_enable(
                child,
                level=lvl,
                login_password=pw,
                enable_password=en_pw,
                timeout=timeout,
                out_chunks=out_chunks,
            )

        for cmd in commands:
            cmd = "" if cmd is None else str(cmd)
            cmd = cmd.rstrip("\n")
            if not cmd:
                continue
            raw = _run_one_command(child, cmd=cmd, timeout=timeout, out_chunks=out_chunks)
            per_cmd.append(TelnetCommandResult(cmd=cmd, output=_clean_output(raw)))

        try:
            child.sendline("exit")
            child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=2)
        except Exception:
            pass

    finally:
        try:
            child.close(force=True)
        except Exception:
            pass

    lines: list[str] = []
    banner = _clean_output("".join(out_chunks))
    if banner.strip() and debug:
        lines.append("=== CONNECT/LOGIN (raw-ish) ===")
        lines.append(banner.strip())

    lines.append(f"=== OLT TELNET JOB: {host} ===")

    for item in per_cmd:
        lines.append("")
        lines.append(f"$ {item.cmd}")
        out = (item.output or "").strip()
        if out:
            lines.append(out)

    text = "\n".join(lines).strip() + "\n"
    if max_output_chars and len(text) > int(max_output_chars):
        text = text[: int(max_output_chars)] + "\n... (truncated)\n"

    return text

