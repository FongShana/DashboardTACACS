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

    for u in users:
        if (u.get("username") or "").strip() == username:
            u["roles"] = role      # ใช้ key 'roles' ตาม policy ของคุณ
            u["status"] = status
            u.setdefault("last_login", "-")
            if gids is not None:
                u["device_group_ids"] = gids
            save_policy(policy)
            return False

    rec: Dict[str, Any] = {
        "username": username,
        "roles": role,
        "status": status,
        "last_login": "-",
    }
    if gids is not None:
        rec["device_group_ids"] = gids

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


