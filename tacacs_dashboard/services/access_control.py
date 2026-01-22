"""Access control helpers for scoping web-admin operations to device groups.

Design:
- superadmin: full access (allowed_group_ids = None)
- admin: access only to groups assigned in web_users.json (allowed_group_ids = list)

This module is intentionally small and framework-agnostic (no Flask imports).
Routes should pass (role, web_username) explicitly.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .web_users_store import ROLE_SUPERADMIN, get_user_device_group_ids


def allowed_device_group_ids(role: str, web_username: str) -> Optional[List[str]]:
    role = (role or "").strip().lower()
    if role == ROLE_SUPERADMIN:
        return None
    return get_user_device_group_ids(web_username)


def device_in_scope(device: Dict[str, Any], allowed_group_ids: Optional[List[str]]) -> bool:
    if allowed_group_ids is None:
        return True
    gid = (device.get("group_id") or "").strip()
    return bool(gid) and gid in allowed_group_ids
