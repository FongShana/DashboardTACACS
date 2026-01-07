#!/usr/bin/env python3
import json
import os
import sys
import re
import getpass
import pexpect

from tacacs_dashboard.services.privilege import parse_privilege

PROMPT_RE = re.compile(r"[>#]\s*$", re.M)
PASS_RE = re.compile(r"(?i)password:")
LOGIN_RE = re.compile(r"(?i)(username:|login:)")
DENIED_RE = re.compile(r"(?i)(denied|failed|incorrect|invalid|not authorized)")
MORE_RE = re.compile(r"--More--")

ROLE_TO_ENABLE = {"OLT_VIEW": 1, "OLT_ENGINEER": 7, "OLT_ADMIN": 15}


def load_policy(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def role_of_user(policy: dict, username: str) -> str:
    for u in policy.get("users", []):
        if u.get("username", "").lower() == username.lower():
            return u.get("roles", "")
    raise SystemExit(f"User {username} not found in policy.json")


def enable_level_for_role(policy: dict, role: str) -> int:
    # ใช้ privilege ใน policy roles ก่อน ถ้าไม่มีค่อย fallback mapping
    for r in policy.get("roles", []):
        if r.get("name", "").upper() == role.upper():
            return parse_privilege(r.get("privilege"), default=15)
    return int(ROLE_TO_ENABLE.get(role.upper(), 15))


def _expect_or_die(child: pexpect.spawn, patterns, msg: str, timeout: int = 10) -> int:
    idx = child.expect(patterns + [pexpect.TIMEOUT], timeout=timeout)
    if idx == len(patterns):
        raise SystemExit(msg)
    return idx


def _page_more(child: pexpect.spawn):
    """ถ้า output ติด --More-- ให้กด space ไปเรื่อยๆ จนจบ"""
    while True:
        idx = child.expect([MORE_RE, PROMPT_RE, pexpect.TIMEOUT], timeout=2)
        if idx == 0:
            child.send(" ")
            continue
        break


def main():
    if len(sys.argv) < 2:
        print("Usage: oltcli.py <username> [device_ip]")
        sys.exit(2)

    username = sys.argv[1]
    device_ip = sys.argv[2] if len(sys.argv) >= 3 else os.environ.get("OLT_IP", "10.235.110.28")

    policy_path = os.environ.get("POLICY_JSON", "./policy.json")
    policy = load_policy(policy_path)

    role = role_of_user(policy, username)
    level = enable_level_for_role(policy, role)

    print(f"[oltcli] user={username} role={role} -> enable {level}")

    password = getpass.getpass("Login password: ")

    child = pexpect.spawn("/usr/bin/telnet", [device_ip], encoding="utf-8", timeout=10)

    # ถ้าต้องการ debug ตอน login ให้เปิดบรรทัดนี้ได้ (แต่ปิดก่อน interact)
    child.logfile_read = sys.stdout
    child.logfile_send = None

    # รอ prompt Username/login (ZTE บางทีพิมพ์ banner ก่อน)
    _expect_or_die(
        child,
        [LOGIN_RE],
        "Timeout waiting for Username prompt",
        timeout=15,
    )
    child.sendline(username)

    _expect_or_die(
        child,
        [PASS_RE],
        "Timeout waiting for Password prompt",
        timeout=15,
    )
    child.sendline(password)

    # รอ prompt หรือโดน deny
    idx = child.expect([PROMPT_RE, DENIED_RE, pexpect.TIMEOUT], timeout=20)
    if idx == 1:
        raise SystemExit("Login denied")
    if idx == 2:
        raise SystemExit("Timeout waiting for CLI prompt after login")

    # auto enable ตาม role
    if (child.after or "").strip().endswith(">"):
        child.sendline(f"enable {level}")
        i = child.expect([PASS_RE, PROMPT_RE, DENIED_RE, pexpect.TIMEOUT], timeout=15)

        if i == 0:
            # ใช้ login password (รองรับ enable <level> = login)
            child.sendline(password)
            i2 = child.expect([PROMPT_RE, DENIED_RE, pexpect.TIMEOUT], timeout=15)
            if i2 == 1:
                raise SystemExit("Enable denied")
            if i2 == 2:
                raise SystemExit("Enable timeout")
        elif i == 2:
            raise SystemExit("Enable denied")
        elif i == 3:
            raise SystemExit("Enable timeout")

    # (optional) แสดงระดับ privilege หลัง enable
    child.sendline("show privilege")
    child.expect([PROMPT_RE, pexpect.TIMEOUT], timeout=10)
    _page_more(child)

    # ก่อน interact ให้ปิด logfile เพื่อกันปัญหา type/การ log ซ้ำ
    child.logfile_read = None

    # interactive terminal
    child.interact()


if __name__ == "__main__":
    main()


