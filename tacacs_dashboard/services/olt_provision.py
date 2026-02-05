# tacacs_dashboard/services/olt_provision.py
from __future__ import annotations

from .tacacs_config import _read_env
from .olt_telnet import telnet_exec_commands
from .policy_store import is_reserved_olt_username

def _select_olt_login_creds(target_username: str | None = None) -> tuple[str, str]:
    """Return (login_user, login_pass) for Telnet provisioning.

    Priority:
    1) OLT_PROVISION_USER / OLT_PROVISION_PASSWORD (service account) if set.
    2) Fallback to legacy OLT_ADMIN_USER / OLT_ADMIN_PASSWORD.

    Special case:
    - When we are provisioning the provisioning account itself (target_username == OLT_PROVISION_USER),
      we MUST use legacy admin credentials, because the provisioning account may not exist yet on the OLT.
    """
    admin_user = (_read_env("OLT_ADMIN_USER", "zte") or "zte").strip()
    admin_pass = _read_env("OLT_ADMIN_PASSWORD", "")

    prov_user = (_read_env("OLT_PROVISION_USER", "") or "").strip()
    prov_pass = _read_env("OLT_PROVISION_PASSWORD", "")

    tu = (target_username or "").strip().lower()
    if prov_user and prov_pass:
        if tu and tu == prov_user.strip().lower():
            # bootstrap the service account itself using legacy admin
            return admin_user, admin_pass
        return prov_user, prov_pass

    return admin_user, admin_pass


def build_provision_commands(username: str, role: str) -> list[str]:
    cmds: list[str] = [
        "conf t",
        "system-user",
        f"user-name {username}",
        "enable-type aaa authentication-template 128",
        "bind authentication-template 128",
        "bind authorization-template 128",
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
    login_user, login_pass = _select_olt_login_creds(target_username=username)
    enable15 = _read_env("OLT_ENABLE15_PASSWORD", "")
    timeout_s = int(_read_env("OLT_TELNET_TIMEOUT", "8") or "8")

    if not login_pass:
        raise RuntimeError("OLT_PROVISION_PASSWORD (or fallback OLT_ADMIN_PASSWORD) not set in secret.env")

    # Safety: don't create/modify reserved usernames, or the account we are currently using to login
    if is_reserved_olt_username(username) or (username or "").strip().lower() == (login_user or "").strip().lower():
        raise RuntimeError(f"Refusing to provision reserved/unsafe username '{username}' on OLT")

    cmds = build_provision_commands(username=username, role=role)
    if save:
        cmds.append("write")

    if dry_run:
        return "DRY-RUN (no changes)\n" + "\n".join(cmds)

    return telnet_exec_commands(
        host=olt_ip,
        admin_user=login_user,
        admin_pass=login_pass,
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
    admin_user = (_read_env("OLT_ADMIN_USER", "zte") or "zte").strip()
    prov_user = (_read_env("OLT_PROVISION_USER", "") or "").strip()

    # Safety: never delete reserved/critical accounts via automation
    if is_reserved_olt_username(username) or (username or "").strip().lower() in {admin_user.lower(), prov_user.lower()}:
        raise RuntimeError(f"Refuse to delete critical username '{username}' on OLT")

    login_user, login_pass = _select_olt_login_creds(target_username=username)
    enable15 = _read_env("OLT_ENABLE15_PASSWORD", "")
    timeout_s = int(_read_env("OLT_TELNET_TIMEOUT", "8") or "8")

    if not login_pass:
        raise RuntimeError("OLT_PROVISION_PASSWORD (or fallback OLT_ADMIN_PASSWORD) not set in secret.env")

    cmds = build_deprovision_commands(username=username)
    if save:
        cmds.append("write")

    if dry_run:
        return "DRY-RUN (no changes)\n" + "\n".join(cmds)

    return telnet_exec_commands(
        host=olt_ip,
        admin_user=login_user,
        admin_pass=login_pass,
        enable_pass=enable15,
        commands=cmds,
        timeout=timeout_s,
    )

