# tacacs_dashboard/services/olt_provision.py
from __future__ import annotations

from .tacacs_config import _read_env
from .olt_telnet import telnet_exec_commands


def role_to_author_template(role: str) -> int:
    role = (role or "").strip()
    if role == "OLT_ADMIN":
        return 128
    if role == "OLT_ENGINEER":
        return 127
    return 126


def build_provision_commands(username: str, role: str) -> list[str]:
    author_t = role_to_author_template(role)
    cmds: list[str] = [
        "conf t",
        "system-user",
        f"user-name {username}",
        "bind authentication-template 128",
        f"bind authorization-template {author_t}",
    ]
    if role in ("OLT_ADMIN", "OLT_ENGINEER"):
        cmds.append("enable-type aaa authentication-template 128")

    cmds += ["exit", "end"]
    return cmds


def provision_user_on_olt(
    olt_ip: str,
    username: str,
    role: str,
    *,
    save: bool = False,
    dry_run: bool = False,
) -> str:
    admin_user = _read_env("OLT_ADMIN_USER", "zte")
    admin_pass = _read_env("OLT_ADMIN_PASSWORD", "")
    enable15 = _read_env("OLT_ENABLE15_PASSWORD", "")
    timeout_s = int(_read_env("OLT_TELNET_TIMEOUT", "8") or "8")

    if not admin_pass:
        raise RuntimeError("OLT_ADMIN_PASSWORD not set in secret.env")

    cmds = build_provision_commands(username=username, role=role)
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


# ------------------------
# ✅ เพิ่ม “ลบ user” ตรงนี้
# ------------------------
def build_deprovision_commands(username: str) -> list[str]:
    # ลบเฉพาะ user-name เป้าหมาย ไม่แตะ zte
    return [
        "conf t",
        "system-user",
        f"no user-name {username}",
        "end",
    ]


def deprovision_user_on_olt(
    olt_ip: str,
    username: str,
    *,
    save: bool = False,
    dry_run: bool = False,
) -> str:
    admin_user = _read_env("OLT_ADMIN_USER", "zte")
    admin_pass = _read_env("OLT_ADMIN_PASSWORD", "")
    enable15 = _read_env("OLT_ENABLE15_PASSWORD", "")
    timeout_s = int(_read_env("OLT_TELNET_TIMEOUT", "8") or "8")

    if not admin_pass:
        raise RuntimeError("OLT_ADMIN_PASSWORD not set in secret.env")

    # กันพลาด: ไม่ให้ลบ user admin ที่ใช้ provision อยู่
    if username == admin_user:
        raise RuntimeError(f"Refuse to delete admin_user '{admin_user}' on OLT")

    cmds = build_deprovision_commands(username=username)
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

