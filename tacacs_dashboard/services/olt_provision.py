# tacacs_dashboard/services/olt_provision.py
from __future__ import annotations

from .tacacs_config import _read_env  # ใช้ตัวอ่าน env ที่มีอยู่แล้ว
from .olt_telnet import telnet_exec_commands


def role_to_author_template(role: str) -> int:
    """
    map role -> authorization-template number บน OLT
      - OLT_ADMIN    -> 128
      - OLT_ENGINEER -> 127
      - OLT_VIEW     -> 126 (default)
    """
    role = (role or "").strip()
    if role == "OLT_ADMIN":
        return 128
    if role == "OLT_ENGINEER":
        return 127
    return 126


def build_provision_commands(username: str, role: str) -> list[str]:
    """
    สร้างชุดคำสั่งสำหรับ provision/bind template ให้ user เป้าหมาย
    *ไม่ยุ่งกับ zte* เพราะเราเข้าไปที่ user-name <username> เท่านั้น
    """
    author_t = role_to_author_template(role)

    cmds: list[str] = [
        "conf t",
        "system-user",
        f"user-name {username}",
        # login AAA เหมือนเดิม
        "bind authentication-template 128",
        # bind สิทธิ์ตาม role
        f"bind authorization-template {author_t}",
    ]

    # Engineer/Admin: ตั้ง enable-type ให้ถาม enable แล้วไปใช้ AAA template 128
    # View: ไม่ใส่ เพื่อให้ enable ไม่ได้
    if role in ("OLT_ADMIN", "OLT_ENGINEER"):
        cmds.append("enable-type aaa authentication-template 128")

    # ออกจากโหมด user-name -> system-user -> privileged
    cmds += [
        "exit",
        "end",
    ]
    return cmds


def provision_user_on_olt(
    olt_ip: str,
    username: str,
    role: str,
    *,
    save: bool = False,
    dry_run: bool = False,
) -> str:
    """
    Provision user บน OLT ผ่าน telnet โดย bind template ตาม role

    - save=False (default): ไม่ write กันพังตอนเทส
    - dry_run=True: ไม่ telnet จริง คืนค่ารายการคำสั่งที่จะยิง
    """
    admin_user = _read_env("OLT_ADMIN_USER", "zte")
    admin_pass = _read_env("OLT_ADMIN_PASSWORD", "")
    enable15 = _read_env("OLT_ENABLE15_PASSWORD", "")
    timeout_s = int(_read_env("OLT_TELNET_TIMEOUT", "8") or "8")

    if not admin_pass:
        raise RuntimeError("OLT_ADMIN_PASSWORD not set in secret.env")

    cmds = build_provision_commands(username=username, role=role)

    # ✅ เฉพาะตอนมั่นใจแล้วค่อย save
    if save:
        cmds.append("write")

    if dry_run:
        return "DRY-RUN (no changes)\n" + "\n".join(cmds)

    return telnet_exec_commands(
        host=olt_ip,
        admin_user=admin_user,
        admin_pass=admin_pass,
        enable_pass=enable15,
        commands=cmds,
        timeout=timeout_s,
    )

