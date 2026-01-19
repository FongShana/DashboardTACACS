# tacacs_dashboard/services/olt_bootstrap.py
from __future__ import annotations

"""Bootstrap an OLT with the AAA templates used by this dashboard.

Scope (by design):
- Configure AAA templates (default ID=2128) as tacacs-local
- Bind system-user templates (default ID=128) to those AAA templates
- Optionally `write` to save running-config

This intentionally does *not* touch global TACACS settings (tacacs enable,
source-interface vlanXX, tacacs-server host, group-server, etc.) because those
require site/VLAN-specific information and are safer to do manually first.

Environment overrides (secret.env):
- OLT_TACACS_GROUP=zte1
- OLT_AAA_TEMPLATE_ID=2128
- OLT_SYSTEM_USER_TEMPLATE_ID=128
- OLT_CLI_EXIT_STYLE=exit   (or set to '$' if your ZTE CLI prefers "$" to exit a block)
- OLT_TELNET_TIMEOUT=8
- OLT_ADMIN_USER=zte
- OLT_ADMIN_PASSWORD=...
- OLT_ENABLE15_PASSWORD=...  (optional)
- TACACS_ENABLE_PASSWORD=... (fallback)
"""

from typing import List, Optional

from .tacacs_config import _read_env
from .olt_telnet import telnet_exec_commands


AAA_GROUP_NAME_DEFAULT = "zte1"
AAA_TEMPLATE_ID_DEFAULT = 2128
SYSTEM_USER_TEMPLATE_ID_DEFAULT = 128


def _exit_cmd(exit_style: str) -> str:
    s = (exit_style or "").strip()
    if s == "$":
        return "$"
    return "exit"


def build_bootstrap_commands(
    *,
    aaa_group_name: str = AAA_GROUP_NAME_DEFAULT,
    aaa_template_id: int = AAA_TEMPLATE_ID_DEFAULT,
    sys_template_id: int = SYSTEM_USER_TEMPLATE_ID_DEFAULT,
    exit_style: str = "exit",
) -> List[str]:
    """Return CLI commands to bootstrap AAA templates + system-user binds."""

    g = (aaa_group_name or AAA_GROUP_NAME_DEFAULT).strip() or AAA_GROUP_NAME_DEFAULT
    aaa_id = int(aaa_template_id)
    sys_id = int(sys_template_id)
    x = _exit_cmd(exit_style)

    # NOTE: We avoid leading spaces (safer with pexpect + telnet)
    cmds: List[str] = [
        "conf t",

        # ----- AAA templates (tacacs-local) -----
        f"aaa-accounting-template {aaa_id}",
        "aaa-accounting-type tacacs",
        f"accounting-tacacs-group {g}",
        "description TACACS_ACCT",
        x,

        f"aaa-authentication-template {aaa_id}",
        "aaa-authentication-type tacacs-local",
        f"authentication-tacacs-group {g}",
        x,

        f"aaa-authorization-template {aaa_id}",
        "aaa-authorization-type tacacs-local",
        f"authorization-tacacs-group {g}",
        x,

        # ----- system-user binds -----
        "system-user",
        f"account-switch on accounting-template {aaa_id}",

        f"authorization-template {sys_id}",
        f"bind aaa-authorization-template {aaa_id}",
        x,

        f"authentication-template {sys_id}",
        f"bind aaa-authentication-template {aaa_id}",
        x,

        x,      # exit system-user

        f"command-authorization 5 {aaa_id}",

        "end",  # leave config mode
    ]
    return cmds


def bootstrap_device_on_olt(
    ip: str,
    *,
    save: bool = False,
    dry_run: bool = False,
    timeout: Optional[int] = None,
    debug: bool = False,
) -> str:
    """Connect to an OLT (telnet) and apply bootstrap commands.

    - Uses OLT_ADMIN_USER / OLT_ADMIN_PASSWORD from secret.env.
    - If enable is required, uses OLT_ENABLE15_PASSWORD (or TACACS_ENABLE_PASSWORD).

    Returns: text output grouped per command (good for flashing in UI).
    """

    ip = (ip or "").strip()
    if not ip:
        raise ValueError("ip is required")

    admin_user = (_read_env("OLT_ADMIN_USER", "zte") or "zte").strip()
    admin_pass = (_read_env("OLT_ADMIN_PASSWORD", "") or "").strip()
    if not admin_pass:
        raise RuntimeError("OLT_ADMIN_PASSWORD not set in secret.env")

    # enable password can be empty (some devices use same as login or don't ask)
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

    exit_style = (_read_env("OLT_CLI_EXIT_STYLE", "exit") or "exit").strip() or "exit"

    cmds = build_bootstrap_commands(
        aaa_group_name=g,
        aaa_template_id=aaa_id,
        sys_template_id=sys_id,
        exit_style=exit_style,
    )
    if save:
        cmds = cmds + ["write"]

    if dry_run:
        return "DRY-RUN (no changes)\n" + "\n".join(cmds)

    return telnet_exec_commands(
        ip,
        commands=cmds,
        timeout=int(timeout),
        admin_user=admin_user,
        admin_pass=admin_pass,
        enable_pass=enable_pw,
        auto_enable=True,
        enable_level=15,
        debug=debug,
    )

