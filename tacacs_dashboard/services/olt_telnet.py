from __future__ import annotations
import re
import time
from pathlib import Path
import pexpect

PROMPT_RE = re.compile(r"[>#]\s*$")

def telnet_exec_commands(
    host: str,
    admin_user: str,
    admin_pass: str,
    enable_pass: str | None,
    commands: list[str],
    timeout: int = 8,
) -> str:
    """
    เปิด telnet -> login -> (enable ถ้าจำเป็น) -> ยิง commands -> ออก
    คืนค่า output ทั้งหมด (เผื่อ debug)
    """
    child = pexpect.spawn(f"telnet {host}", encoding="utf-8", timeout=timeout)
    out_chunks: list[str] = []

    def _expect(patterns):
        idx = child.expect(patterns)
        out_chunks.append(child.before or "")
        out_chunks.append(child.after or "")
        return idx

    def _send(cmd: str):
        child.sendline(cmd)
        time.sleep(0.1)

    try:
        # login
        _expect([r"(Username:|login:)", r"Connected", r"Escape character", pexpect.TIMEOUT])
        if "Username" in (child.after or "") or "login" in (child.after or ""):
            _send(admin_user)
            _expect([r"Password:", pexpect.TIMEOUT])
            _send(admin_pass)
        else:
            # บางรุ่นมันพิมพ์หลายบรรทัดก่อนถึง Username
            _expect([r"(Username:|login:)", pexpect.TIMEOUT])
            _send(admin_user)
            _expect([r"Password:", pexpect.TIMEOUT])
            _send(admin_pass)

        # เข้าสู่ prompt
        _expect([PROMPT_RE, r"(Login incorrect|Bad password)", pexpect.TIMEOUT])

        # ถ้าอยู่ที่ '>' ให้ enable
        if (child.after or "").strip().endswith(">"):
            _send("enable")
            _expect([r"Password:", PROMPT_RE, pexpect.TIMEOUT])
            # บางรุ่นถาม enable password
            if "Password:" in (child.after or ""):
                if not enable_pass:
                    raise RuntimeError("OLT asks enable password but OLT_ENABLE15_PASSWORD not set")
                _send(enable_pass)
                _expect([PROMPT_RE, r"(Bad password|denied)", pexpect.TIMEOUT])

        # ยิงคำสั่ง
        for cmd in commands:
            _send(cmd)
            # handle --More-- (ถ้ามี)
            while True:
                idx = child.expect([PROMPT_RE, r"--More--", pexpect.TIMEOUT], timeout=timeout)
                out_chunks.append(child.before or "")
                out_chunks.append(child.after or "")
                if idx == 1:
                    child.send(" ")  # next page
                    continue
                break

        _send("exit")
        # บางรุ่นต้อง exit 2 ครั้ง
        child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=3)

    finally:
        try:
            child.close(force=True)
        except Exception:
            pass

    return "".join(out_chunks)
