# tacacs_dashboard/services/policy_store.py
from __future__ import annotations
from pathlib import Path
import json
from typing import Any, Dict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
POLICY_PATH = BASE_DIR / "policy.json"


def load_policy() -> Dict[str, Any]:
    # กันกรณีไฟล์ยังไม่ถูกสร้าง
    if not POLICY_PATH.exists():
        return {"users": [], "roles": [], "devices": []}

    raw = POLICY_PATH.read_text(encoding="utf-8").strip()
    if not raw:
        return {"users": [], "roles": [], "devices": []}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # ถ้าไฟล์พัง ให้ fallback (หรือจะ raise ก็ได้)
        return {"users": [], "roles": [], "devices": []}

    # กัน key หาย
    data.setdefault("users", [])
    data.setdefault("roles", [])
    data.setdefault("devices", [])
    return data


def save_policy(policy: Dict[str, Any]) -> None:
    tmp = POLICY_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(POLICY_PATH)


def upsert_user(username: str, role: str, status: str = "Active") -> bool:
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

    for u in users:
        if (u.get("username") or "").strip() == username:
            u["roles"] = role      # ใช้ key 'roles' ตาม policy ของคุณ
            u["status"] = status
            u.setdefault("last_login", "-")
            save_policy(policy)
            return False

    users.append({
        "username": username,
        "roles": role,
        "status": status,
        "last_login": "-",
    })
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

