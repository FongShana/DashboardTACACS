# tacacs_dashboard/services/olt_provision.py
from __future__ import annotations

from .tacacs_config import _read_env
from .olt_telnet import telnet_exec_commands
from .policy_store import is_reserved_olt_username


def _guard_deprovision_provision_user(*, olt_ip: str, username: str) -> None:
    """Safety guard: prevent removing the provisioning account when zte is locked down.

    Rationale:
    - In this project, when local account `zte` is switched to Template 128, it is
      effectively a break-glass account and often cannot login while TACACS is up.
    - If we delete the provisioning account (e.g., `tac_prov`) from that OLT while
      `zte` is on Template 128, the dashboard may not be able to add it back via
      local login, creating a lock-out risk.

    Policy:
    - Allow deprovision only when `zte` is confirmed on Template 1.
    - If template is 128/unknown/mismatch/other -> block.
    """
    prov_user = (_read_env("OLT_PROVISION_USER", "") or "").strip()
    if not prov_user:
        return

    if (username or "").strip().lower() != prov_user.lower():
        return

    # Lazy import to avoid extra cost for non-provision-user paths.
    from .zte_template_status import get_zte_template_status, template_label

    st = get_zte_template_status(olt_ip)
    if (getattr(st, "template", "") or "").strip() != "1":
        lbl = template_label(st)
        raise RuntimeError(
            f"Refusing to remove provisioning user '{prov_user}' from OLT {olt_ip}. "
            f"Local account 'zte' is currently {lbl}. "
            f"Please revert zte to Template 1 first (Users & Roles -> Local Account (zte) -> Revert), "
            f"then try again."
        )



def _select_olt_login_creds(*, target_username: str) -> tuple[str, str]:
    """Pick telnet login credentials for OLT provisioning.

    Preference order:
    1) OLT_PROVISION_USER/PASSWORD (TACACS service account) if set
    2) OLT_ADMIN_USER/PASSWORD (legacy local admin) fallback

    Safety:
    - When provisioning the provisioning account itself (target_username == OLT_PROVISION_USER),
      force use of legacy admin to avoid chicken-and-egg on new OLTs.
    """
    prov_user = (_read_env("OLT_PROVISION_USER", "") or "").strip()
    prov_pass = (_read_env("OLT_PROVISION_PASSWORD", "") or "").strip()
    admin_user = (_read_env("OLT_ADMIN_USER", "zte") or "zte").strip()
    admin_pass = (_read_env("OLT_ADMIN_PASSWORD", "") or "").strip()

    if not prov_user or not prov_pass:
        return admin_user, admin_pass

    if (target_username or "").strip().lower() == prov_user.lower():
        return admin_user, admin_pass

    return prov_user, prov_pass

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
        raise RuntimeError("OLT_PROVISION_PASSWORD or OLT_ADMIN_PASSWORD not set in secret.env")

    if is_reserved_olt_username(username) or (username or '').strip().lower() == (login_user or '').strip().lower():
        raise RuntimeError(f"Refusing to provision reserved username '{username}' on OLT")

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
    login_user, login_pass = _select_olt_login_creds(target_username=username)
    enable15 = _read_env("OLT_ENABLE15_PASSWORD", "")
    timeout_s = int(_read_env("OLT_TELNET_TIMEOUT", "8") or "8")

    if not login_pass:
        raise RuntimeError("OLT_PROVISION_PASSWORD or OLT_ADMIN_PASSWORD not set in secret.env")

    # Safety: do not allow removing provisioning account if zte is not Template 1.
    _guard_deprovision_provision_user(olt_ip=olt_ip, username=username)

    # กันพลาด: ไม่ให้ลบ account ที่ใช้ provision อยู่
    if (username or '').strip().lower() == (login_user or '').strip().lower():
        raise RuntimeError(f"Refuse to delete login_user '{login_user}' on OLT")
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


# ------------------------
# Emergency / maintenance
# ------------------------
def switch_user_templates_on_olt(
    olt_ip: str,
    username: str,
    *,
    auth_template: str,
    author_template: str,
    save: bool = True,
    dry_run: bool = False,
) -> str:
    """Switch a system-user's authentication/authorization templates on a specific OLT.

    Prefer TACACS provisioning account if configured (OLT_PROVISION_USER/PASSWORD),
    otherwise fallback to legacy OLT_ADMIN_USER/PASSWORD.

    NOTE:
    - For ZTE C600 in this project, local system-user entry must exist for TACACS login.
    - This function is intended for controlled admin operations only.
    """
    # Prefer TACACS provisioning account (service account), fallback to legacy local admin.
    prov_user = (_read_env("OLT_PROVISION_USER", "") or "").strip()
    prov_pass = (_read_env("OLT_PROVISION_PASSWORD", "") or "").strip()
    admin_user = (_read_env("OLT_ADMIN_USER", "zte") or "zte").strip()
    admin_pass = (_read_env("OLT_ADMIN_PASSWORD", "") or "").strip()

    enable15 = _read_env("OLT_ENABLE15_PASSWORD", "")
    timeout_s = int(_read_env("OLT_TELNET_TIMEOUT", "8") or "8")

    # Choose login credential
    login_user = admin_user
    login_pass = admin_pass
    if prov_user and prov_pass:
        login_user = prov_user
        login_pass = prov_pass

    if not login_pass:
        raise RuntimeError("OLT_ADMIN_PASSWORD/OLT_PROVISION_PASSWORD not set in secret.env")

    cmds = [
        "conf t",
        "system-user",
        f"user-name {username}",
        f"bind authentication-template {auth_template}",
        f"bind authorization-template {author_template}",
        "end",
    ]
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
