# tacacs_dashboard/services/olt_bootstrap.py
from __future__ import annotations

"""Bootstrap an OLT with the AAA templates used by this dashboard.

Scope (by design):
- Configure AAA templates 2128 (tacacs-local)
- Bind system-user templates 128 to AAA 2128

This intentionally does *not* touch global TACACS settings (tacacs enable,
tacacs-server host, source-interface, group-server, etc.) because those
typically require site/VLAN-specific information and are often done manually.
"""

from typing import List

from .tacacs_config import _read_env
from .olt_telnet import telnet_exec_commands


AAA_GROUP_NAME_DEFAULT = "zte1"
AAA_TEMPLATE_ID_DEFAULT = 2128
SYSTEM_USER_TEMPLATE_ID_DEFAULT = 128


def build_bootstrap_commands(
    *,
    aaa_group_name: str = AAA_GROUP_NAME_DEFAULT,
    aaa_template_id: int = AAA_TEMPLATE_ID_DEFAULT,
    sys_template_id: int = SYSTEM_USER_TEMPLATE_ID_DEFAULT,
) -> List[str]:
    """Return CLI commands to bootstrap AAA templates + system-user binds."""

    g = (aaa_group_name or AAA_GROUP_NAME_DEFAULT).strip() or AAA_GROUP_NAME_DEFAULT
    aaa_id = int(aaa_template_id)
    sys_id = int(sys_template_id)

    cmds: List[str] = [
        "conf t",

        # ----- AAA templates (tacacs-local) -----
        f"aaa-accounting-template {aaa_id}",
        "aaa-accounting-type tacacs",
        f"accounting-tacacs-group {g}",
        "description TACACS_ACCT",
        "exit",

        f"aaa-authentication-template {aaa_id}",
        "aaa-authentication-type tacacs-local",
        f"authentication-tacacs-group {g}",
        "exit",

        f"aaa-authorization-template {aaa_id}",
        "aaa-authorization-type tacacs-local",
        f"authorization-tacacs-group {g}",
        "exit",

        # ----- system-user binds -----
        "system-user",
        f"account-switch on accounting-template {aaa_id}",

        f"authorization-template {sys_id}",
        f"bind aaa-authorization-template {aaa_id}",
        "exit",

        f"authentication-template {sys_id}",
        f"bind aaa-authentication-template {aaa_id}",
        "exit",

        "exit",
        "end",
    ]
    return cmds


def bootstrap_device_on_olt(
    ip: str,
    *,
    save: bool = False,
    dry_run: bool = False,
    timeout: int | None = None,
    debug: bool = False,
) -> str:
    """Connect to OLT (telnet) and apply bootstrap commands.

    Uses OLT_ADMIN_USER / OLT_ADMIN_PASSWORD from secret.env.
    If enable is required, uses OLT_ENABLE15_PASSWORD (or TACACS_ENABLE_PASSWORD) if present.
    """

    ip = (ip or "").strip()
    if not ip:
        raise ValueError("ip is required")

    admin_user = (_read_env("OLT_ADMIN_USER", "zte") or "zte").strip()
    admin_pass = (_read_env("OLT_ADMIN_PASSWORD", "zte") or "zte").strip()

    enable_pw = (_read_env("OLT_ENABLE15_PASSWORD", "") or "").strip()
    if not enable_pw:
        enable_pw = (_read_env("TACACS_ENABLE_PASSWORD", "") or "").strip()
    enable_pw = enable_pw or None

    if timeout is None:
        try:
            timeout = int((_read_env("OLT_TELNET_TIMEOUT", "8") or "8").strip())
        except Exception:
            timeout = 8

    # Allow overriding group/template IDs from env (optional)
    g = (_read_env("OLT_TACACS_GROUP", AAA_GROUP_NAME_DEFAULT) or AAA_GROUP_NAME_DEFAULT).strip()
    try:
        aaa_id = int((_read_env("OLT_AAA_TEMPLATE_ID", str(AAA_TEMPLATE_ID_DEFAULT)) or str(AAA_TEMPLATE_ID_DEFAULT)).strip())
    except Exception:
        aaa_id = AAA_TEMPLATE_ID_DEFAULT
    try:
        sys_id = int((_read_env("OLT_SYSTEM_USER_TEMPLATE_ID", str(SYSTEM_USER_TEMPLATE_ID_DEFAULT)) or str(SYSTEM_USER_TEMPLATE_ID_DEFAULT)).strip())
    except Exception:
        sys_id = SYSTEM_USER_TEMPLATE_ID_DEFAULT

    cmds = build_bootstrap_commands(aaa_group_name=g, aaa_template_id=aaa_id, sys_template_id=sys_id)
    if save:
        cmds = cmds + ["write"]

    if dry_run:
        return "\n".join(cmds)

    return telnet_exec_commands(
        ip,
        username=admin_user,
        password=admin_pass,
        commands=cmds,
        enable_password=enable_pw,
        timeout=int(timeout),
        auto_enable=True,
        enable_level=15,
        debug=debug,
    )
