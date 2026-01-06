# tacacs_dashboard/services/olt_telnet.py
from __future__ import annotations

import re
import time
import shutil
from typing import Optional

import pexpect

# Prompt ของ ZTE: user exec '>' และ privileged '#'
PROMPT_RE = re.compile(r"[>#]\s*$")
PASS_RE = re.compile(r"(?i)password:")
LOGIN_FAIL_RE = re.compile(r"(?i)(login incorrect|bad password|authentication failed)")
DENIED_RE = re.compile(r"(?i)(denied|failed|not authorized|invalid|incorrect)")
MORE_RE = re.compile(r"--More--")

# ✅ Map Role -> Enable level
ROLE_TO_ENABLE = {"OLT_VIEW": 1, "OLT_ENGINEER": 7, "OLT_ADMIN": 15}


def _expect_capture(
    child: pexpect.spawn,
    patterns,
    out_chunks: list[str],
    *,
    timeout: Optional[int] = None,
) -> int:
    """expect แล้วเก็บ output ทั้ง before/after สำหรับ debug"""
    idx = child.expect(patterns, timeout=timeout)
    out_chunks.append(child.before or "")
    out_chunks.append(child.after or "")
    return idx


def _send(child: pexpect.spawn, cmd: str):
    child.sendline(cmd)
    time.sleep(0.1)


def _resolve_enable_level(role: Optional[str], enable_level: Optional[int]) -> int:
    """เลือก enable level จาก role ก่อน ถ้าไม่ส่ง role ค่อยใช้ enable_level; default = 15"""
    if role:
        return int(ROLE_TO_ENABLE.get(role.strip().upper(), 15))
    if enable_level is not None:
        return int(enable_level)
    return 15


def auto_enable_level(
    child: pexpect.spawn,
    out_chunks: list[str],
    *,
    level: int,
    login_password: str,
    enable_password: Optional[str] = None,
    timeout: int = 8,
    verify: bool = False,
) -> int:
    """
    ✅ หลัง login แล้ว “ยกระดับ” อัตโนมัติ: enable <level> แล้วตอบ Password:
    - ถ้ามี enable_password จะส่งอันนั้นก่อน
    - ถ้าไม่มี จะส่ง login_password (รองรับ enable <level> = login ใน pass.secret)
    - verify=True จะยิง show privilege เพื่อตรวจระดับจริง
    """
    # ถ้าอยู่ที่ '>' ให้ยกชั้น
    # (ถ้าอยู่ '# 'แล้วก็ไม่ต้องทำอะไร)
    # หมายเหตุ: เราอิง prompt ล่าสุดที่ child.after
    if (child.after or "").strip().endswith(">"):
        _send(child, f"enable {int(level)}")

        idx = _expect_capture(
            child,
            [PASS_RE, PROMPT_RE, DENIED_RE, pexpect.TIMEOUT],
            out_chunks,
            timeout=timeout,
        )

        if idx == 0:  # Password:
            _send(child, (enable_password or "").strip() or login_password)
            idx2 = _expect_capture(
                child,
                [PROMPT_RE, DENIED_RE, pexpect.TIMEOUT],
                out_chunks,
                timeout=timeout,
            )
            if idx2 != 0:
                raise RuntimeError("Enable failed (password wrong/denied/timeout).")

        elif idx == 1:
            # ได้ prompt กลับมาเลย (บางรุ่นไม่ถาม password)
            pass
        elif idx == 2:
            raise RuntimeError("Enable denied by device/TACACS.")
        else:
            raise RuntimeError("Enable timeout.")

    if not verify:
        return int(level)

    # verify ด้วย show privilege
    _send(child, "show privilege")
    _expect_capture(child, [PROMPT_RE, pexpect.TIMEOUT], out_chunks, timeout=timeout)
    m = re.search(r"Current privilege level is\s+(\d+)", "".join(out_chunks))
    return int(m.group(1)) if m else -1


def telnet_exec_commands(
    host: str,
    admin_user: str,
    admin_pass: str,
    enable_pass: str | None,
    commands: list[str],
    timeout: int = 8,
    *,
    role: str | None = None,
    enable_level: int | None = None,
    auto_enable: bool = True,
) -> str:
    """
    เปิด telnet -> login -> (auto enable ตาม role/enable_level) -> ยิง commands -> ออก
    คืนค่า output ทั้งหมด (เผื่อ debug)

    - ถ้าส่ง role="OLT_VIEW"/"OLT_ENGINEER"/"OLT_ADMIN" จะ auto enable เป็น 1/7/15 ตาม ROLE_TO_ENABLE
    - ถ้าไม่ส่ง role แต่ส่ง enable_level=1/7/15 ก็ทำงานเหมือนกัน
    - ถ้า auto_enable=False จะไม่ยิง enable ให้อัตโนมัติ
    """
    TELNET_BIN = shutil.which("telnet") or "/usr/bin/telnet"
    child = pexpect.spawn(TELNET_BIN, [host], encoding="utf-8", timeout=timeout)
    out_chunks: list[str] = []

    try:
        # login
        _expect_capture(child, [r"(Username:|login:)", r"Connected", r"Escape character", pexpect.TIMEOUT], out_chunks)
        if "Username" in (child.after or "") or "login" in (child.after or ""):
            _send(child, admin_user)
            _expect_capture(child, [r"Password:", pexpect.TIMEOUT], out_chunks)
            _send(child, admin_pass)
        else:
            # บางรุ่นมันพิมพ์หลายบรรทัดก่อนถึง Username
            _expect_capture(child, [r"(Username:|login:)", pexpect.TIMEOUT], out_chunks)
            _send(child, admin_user)
            _expect_capture(child, [r"Password:", pexpect.TIMEOUT], out_chunks)
            _send(child, admin_pass)

        # เข้าสู่ prompt
        idx = _expect_capture(child, [PROMPT_RE, LOGIN_FAIL_RE, pexpect.TIMEOUT], out_chunks)
        if idx == 1:
            raise RuntimeError("Login failed (bad username/password).")
        if idx == 2:
            raise RuntimeError("Login timeout (no prompt).")

        # ✅ auto enable ตาม role/enable_level
        if auto_enable:
            lvl = _resolve_enable_level(role, enable_level)
            # ถ้าอยู่ที่ '>' ให้ยกระดับ
            if (child.after or "").strip().endswith(">"):
                auto_enable_level(
                    child,
                    out_chunks,
                    level=lvl,
                    login_password=admin_pass,
                    enable_password=enable_pass,
                    timeout=timeout,
                    verify=False,
                )
                # หลัง enable ควรเป็น '#'
                _expect_capture(child, [PROMPT_RE, pexpect.TIMEOUT], out_chunks, timeout=timeout)

        # ยิงคำสั่ง
        for cmd in commands:
            _send(child, cmd)

            # handle --More-- (ถ้ามี)
            while True:
                idx2 = child.expect([PROMPT_RE, MORE_RE, pexpect.TIMEOUT], timeout=timeout)
                out_chunks.append(child.before or "")
                out_chunks.append(child.after or "")

                if idx2 == 1:
                    child.send(" ")  # next page
                    continue
                break

        _send(child, "exit")
        # บางรุ่นต้อง exit 2 ครั้ง
        child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=3)

    finally:
        try:
            child.close(force=True)
        except Exception:
            pass

    return "".join(out_chunks)

