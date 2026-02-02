# tacacs_dashboard/services/policy_store.py
from __future__ import annotations
from pathlib import Path
import json
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent.parent
POLICY_PATH = BASE_DIR / "policy.json"

# Usernames that should never be created via dashboard (avoid clashing with vendor/local accounts)
RESERVED_OLT_USERNAMES = {"zte"}


def is_reserved_olt_username(username: str) -> bool:
    return (username or "").strip().lower() in RESERVED_OLT_USERNAMES



def load_policy() -> Dict[str, Any]:
    # กันกรณีไฟล์ยังไม่ถูกสร้าง
    if not POLICY_PATH.exists():
        return {"users": [], "roles": [], "devices": [], "device_groups": []}

    raw = POLICY_PATH.read_text(encoding="utf-8").strip()
    if not raw:
        return {"users": [], "roles": [], "devices": [], "device_groups": []}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # ถ้าไฟล์พัง ให้ fallback (หรือจะ raise ก็ได้)
        return {"users": [], "roles": [], "devices": [], "device_groups": []}

    # กัน key หาย
    data.setdefault("users", [])
    data.setdefault("roles", [])
    data.setdefault("devices", [])
    data.setdefault("device_groups", [])
    return data


def save_policy(policy: Dict[str, Any]) -> None:
    tmp = POLICY_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(POLICY_PATH)


def upsert_user(
    username: str,
    role: str,
    status: str = "Active",
    device_group_ids: Optional[List[str]] = None,
    target_olt_ips: Optional[List[str]] = None,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
) -> bool:
    """
    return True = created, False = updated
    """
    username = (username or "").strip()
    if not username:
        raise ValueError("username is required")

    role = (role or "OLT_VIEW").strip() or "OLT_VIEW"
    status = (status or "Active").strip() or "Active"

    policy = load_policy()
    users = policy.setdefault("users", [])

    # normalize group ids if provided
    gids: Optional[List[str]] = None
    if device_group_ids is not None:
        gids = []
        for g in device_group_ids:
            gg = (g or "").strip().lower()
            if gg and gg not in gids:
                gids.append(gg)

    # If explicitly provided but empty => treat as 'unscoped' (remove key)
    clear_device_groups = (gids is not None and len(gids) == 0)

    # normalize target OLT IPs (optional field; backward compatible)
    ips: Optional[List[str]] = None
    if target_olt_ips is not None:
        ips = []
        for ip in target_olt_ips:
            ip2 = (ip or "").strip()
            if ip2 and ip2 not in ips:
                ips.append(ip2)

    # If explicitly provided but empty => clear key (meaning: all OLTs in scope)
    clear_target_ips = (ips is not None and len(ips) == 0)

    # normalize names (optional fields; backward compatible)
    fn = None if first_name is None else (first_name or "").strip()
    ln = None if last_name is None else (last_name or "").strip()

    for u in users:
        if (u.get("username") or "").strip() == username:
            u["roles"] = role      # ใช้ key 'roles' ตาม policy ของคุณ
            u["status"] = status
            u.setdefault("last_login", "-")

            # Optional fields: first_name / last_name
            # - If caller passes None: don't touch existing
            # - If caller passes empty string: remove key
            if fn is not None:
                if fn:
                    u["first_name"] = fn
                else:
                    u.pop("first_name", None)
            if ln is not None:
                if ln:
                    u["last_name"] = ln
                else:
                    u.pop("last_name", None)

            # Optional field: target_olt_ips
            # - If caller passes None: don't touch existing
            # - If caller passes []: remove key (meaning: all OLTs in scope)
            if ips is not None:
                if clear_target_ips:
                    u.pop("target_olt_ips", None)
                else:
                    u["target_olt_ips"] = ips

            if gids is not None:
                if clear_device_groups:
                    u.pop("device_group_ids", None)
                else:
                    u["device_group_ids"] = gids
            save_policy(policy)
            return False

    rec: Dict[str, Any] = {
        "username": username,
        "roles": role,
        "status": status,
        "last_login": "-",
    }
    if fn:
        rec["first_name"] = fn
    if ln:
        rec["last_name"] = ln
    if gids is not None and not clear_device_groups:
        rec["device_group_ids"] = gids

    # Save only when explicitly set and non-empty
    if ips is not None and not clear_target_ips:
        rec["target_olt_ips"] = ips

    users.append(rec)
    save_policy(policy)
    return True


def delete_user(username: str) -> bool:
    username = (username or "").strip()
    if not username:
        return False

    policy = load_policy()
    users = policy.get("users", [])
    before = len(users)
    policy["users"] = [u for u in users if (u.get("username") or "").strip() != username]
    if len(policy["users"]) == before:
        return False

    save_policy(policy)
    return True



