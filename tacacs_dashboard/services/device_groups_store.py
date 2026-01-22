from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .policy_store import load_policy, save_policy

# group id: lowercase + digits + _ -
GROUP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")


def normalize_group_id(group_id: str) -> str:
    return (group_id or "").strip().lower()


def validate_group_id(group_id: str) -> None:
    gid = normalize_group_id(group_id)
    if not gid:
        raise ValueError("group_id is required")
    if not GROUP_ID_RE.match(gid):
        raise ValueError("group_id must be 2–32 chars: a-z 0-9 _ - (start with a-z/0-9)")


def list_device_groups() -> List[Dict[str, Any]]:
    policy = load_policy()
    groups = policy.get("device_groups") or []
    if not isinstance(groups, list):
        return []
    out: List[Dict[str, Any]] = []
    for g in groups:
        if isinstance(g, dict):
            gid = normalize_group_id(g.get("id") or "")
            name = (g.get("name") or gid or "").strip()
            if gid:
                out.append({"id": gid, "name": name})
    # stable sort
    out.sort(key=lambda x: (x.get("name") or x.get("id") or ""))
    return out


def get_group_name_map() -> Dict[str, str]:
    return {g["id"]: g["name"] for g in list_device_groups()}


def group_exists(group_id: str) -> bool:
    gid = normalize_group_id(group_id)
    return gid in get_group_name_map()


def upsert_device_group(group_id: str, name: str) -> bool:
    """Create or update a device group.

    Returns True if created, False if updated.
    """
    validate_group_id(group_id)
    gid = normalize_group_id(group_id)
    nm = (name or "").strip() or gid

    policy = load_policy()
    groups = policy.setdefault("device_groups", [])
    if not isinstance(groups, list):
        groups = []
        policy["device_groups"] = groups

    for g in groups:
        if isinstance(g, dict) and normalize_group_id(g.get("id") or "") == gid:
            g["id"] = gid
            g["name"] = nm
            save_policy(policy)
            return False

    groups.append({"id": gid, "name": nm})
    save_policy(policy)
    return True


def delete_device_group(group_id: str) -> None:
    """Delete a device group. Raises if any device is still assigned to it."""
    gid = normalize_group_id(group_id)
    if not gid:
        raise ValueError("group_id is required")

    policy = load_policy()
    devices = policy.get("devices") or []
    if isinstance(devices, list):
        in_use = [d for d in devices if isinstance(d, dict) and (d.get("group_id") or "").strip() == gid]
        if in_use:
            raise ValueError(f"cannot delete group '{gid}': {len(in_use)} device(s) still assigned")

    groups = policy.get("device_groups") or []
    if not isinstance(groups, list):
        return
    before = len(groups)
    policy["device_groups"] = [g for g in groups if not (isinstance(g, dict) and normalize_group_id(g.get("id") or "") == gid)]
    if len(policy["device_groups"]) == before:
        raise ValueError("group not found")

    save_policy(policy)
