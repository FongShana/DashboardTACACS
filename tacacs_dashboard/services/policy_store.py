# tacacs_dashboard/services/policy_store.py
from __future__ import annotations

from pathlib import Path
import json
from typing import Any, Dict, List, Optional, Callable, TypeVar

from .locks import exclusive_lock

BASE_DIR = Path(__file__).resolve().parent.parent.parent
POLICY_PATH = BASE_DIR / "policy.json"

# Usernames that should never be created via dashboard (avoid clashing with vendor/local accounts)
RESERVED_OLT_USERNAMES = {"zte"}


def is_reserved_olt_username(username: str) -> bool:
    return (username or "").strip().lower() in RESERVED_OLT_USERNAMES


def _empty_policy() -> Dict[str, Any]:
    return {"users": [], "roles": [], "devices": [], "device_groups": []}


def _load_policy_unlocked() -> Dict[str, Any]:
    # กันกรณีไฟล์ยังไม่ถูกสร้าง
    if not POLICY_PATH.exists():
        return _empty_policy()

    raw = POLICY_PATH.read_text(encoding="utf-8").strip()
    if not raw:
        return _empty_policy()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # ถ้าไฟล์พัง ให้ fallback (หรือจะ raise ก็ได้)
        return _empty_policy()

    # กัน key หาย (backward compatible)
    data.setdefault("users", [])
    data.setdefault("roles", [])
    data.setdefault("devices", [])
    data.setdefault("device_groups", [])
    return data


def load_policy() -> Dict[str, Any]:
    """Read policy.json.

    Reads are safe because writes are atomic (tmp -> replace). We keep this
    lock-free for performance. For modifications, use update_policy().
    """
    return _load_policy_unlocked()


def _save_policy_unlocked(policy: Dict[str, Any]) -> None:
    tmp = POLICY_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(policy, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(POLICY_PATH)


def save_policy(policy: Dict[str, Any]) -> None:
    """Write policy.json under an exclusive lock.

    NOTE: This does NOT prevent lost updates if callers do load->modify->save
    without holding the same lock. Prefer update_policy() for any mutation.
    """
    with exclusive_lock("policy"):
        _save_policy_unlocked(policy)


T = TypeVar("T")


def update_policy(mutator: Callable[[Dict[str, Any]], T]) -> T:
    """Atomic, locked read-modify-write for policy.json."""
    with exclusive_lock("policy"):
        policy = _load_policy_unlocked()
        result = mutator(policy)
        _save_policy_unlocked(policy)
        return result


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

    def _mut(policy: Dict[str, Any]) -> bool:
        users = policy.setdefault("users", [])

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
        return True

    return update_policy(_mut)


def delete_user(username: str) -> bool:
    username = (username or "").strip()
    if not username:
        return False

    def _mut(policy: Dict[str, Any]) -> bool:
        users = policy.get("users", [])
        before = len(users)
        policy["users"] = [u for u in users if (u.get("username") or "").strip() != username]
        return len(policy["users"]) != before

    return update_policy(_mut)
