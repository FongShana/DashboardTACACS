#!/usr/bin/env python3
import json
import os
import sys
import re
import getpass
from zoneinfo import ZoneInfo
import pexpect

PROMPT_RE = re.compile(r"[>#]\s*$", re.M)
PASS_RE = re.compile(r"(?i)password:")
LOGIN_RE = re.compile(r"(?i)(username:|login:)")
DENIED_RE = re.compile(r"(?i)(denied|failed|incorrect|invalid|not authorized)")

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
            try:
                return int(r.get("privilege", "15"))
            except Exception:
                break
    return int(ROLE_TO_ENABLE.get(role.upper(), 15))

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
    child.logfile_read = sys.stdout
    child.logfile_send = None

    # login prompts
    child.expect([LOGIN_RE, pexpect.TIMEOUT])
    child.sendline(username)

    child.expect([PASS_RE, pexpect.TIMEOUT])
    child.sendline(password)

    # wait prompt
    child.expect([PROMPT_RE, DENIED_RE, pexpect.TIMEOUT])
    if DENIED_RE.search(child.after or ""):
        raise SystemExit("Login denied")

    # auto enable
    if (child.after or "").strip().endswith(">"):
        child.sendline(f"enable {level}")
        i = child.expect([PASS_RE, PROMPT_RE, DENIED_RE, pexpect.TIMEOUT], timeout=10)
        if i == 0:
            # ใช้ login password (รองรับ enable <level> = login)
            child.sendline(password)
            i2 = child.expect([PROMPT_RE, DENIED_RE, pexpect.TIMEOUT], timeout=10)
            if i2 != 0:
                raise SystemExit("Enable failed")
        elif i == 2:
            raise SystemExit("Enable denied")
        elif i == 3:
            raise SystemExit("Enable timeout")

    # interactive
    child.interact()

if __name__ == "__main__":
    main()
