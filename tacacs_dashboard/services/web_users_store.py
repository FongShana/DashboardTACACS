from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent.parent.parent



ROLE_SUPERADMIN = 'superadmin'
ROLE_ADMIN = 'admin'
ALLOWED_ROLES = {ROLE_SUPERADMIN, ROLE_ADMIN}
def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _users_path() -> Path:
    # Allow override for deployments
    p = os.getenv("DASHBOARD_USERS_FILE", "")
    if p.strip():
        return Path(p).expanduser()
    return BASE_DIR / "web_users.json"


def load_web_users() -> Dict[str, Any]:
    path = _users_path()
    if not path.exists():
        return {"version": 1, "users": []}
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return {"version": 1, "users": []}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"version": 1, "users": []}
    data.setdefault("version", 1)
    data.setdefault("users", [])
    return data


def save_web_users(data: Dict[str, Any]) -> None:
    path = _users_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def ensure_bootstrap_admin() -> None:
    """Ensure there is at least one *superadmin* account for dashboard login.

    - If web_users.json already has users: do nothing
    - Else: create a bootstrap account from secret.env
      (DASHBOARD_ADMIN_USER / DASHBOARD_ADMIN_PASSWORD) with role "superadmin".

    หมายเหตุ: เพื่อความปลอดภัย ฟังก์ชันนี้จะไม่สร้างบัญชีด้วยรหัสผ่านค่าเริ่มต้น
    หากไม่ได้กำหนด DASHBOARD_ADMIN_PASSWORD ไว้ในระบบ
    """
    data = load_web_users()
    users: List[Dict[str, Any]] = data.get("users") or []
    if users:
        return

    super_user = (os.getenv("DASHBOARD_ADMIN_USER") or "superadmin").strip() or "superadmin"
    super_pass = os.getenv("DASHBOARD_ADMIN_PASSWORD")
    if not super_pass:
        return

    users.append(
        {
            "username": super_user,
            "role": ROLE_SUPERADMIN,
            "password_hash": generate_password_hash(super_pass),
            "created_at": _now_iso(),
        }
    )
    data["users"] = users
    save_web_users(data)

def authenticate(username: str, password: str) -> Optional[Dict[str, Any]]:
    ensure_bootstrap_admin()
    username = (username or "").strip()
    password = password or ""
    data = load_web_users()
    for u in (data.get("users") or []):
        if (u.get("username") or "").strip() == username:
            if check_password_hash(u.get("password_hash") or "", password):
                role = (u.get("role") or ROLE_ADMIN).strip().lower()
                return {"username": username, "role": role}
            return None
    return None

def list_users() -> List[Dict[str, Any]]:
    ensure_bootstrap_admin()
    data = load_web_users()
    users = data.get("users") or []

    # sort: superadmin first, then admin, then username
    def key(u: Dict[str, Any]):
        r = (u.get("role") or "").strip().lower()
        bucket = 0 if r == ROLE_SUPERADMIN else (1 if r == ROLE_ADMIN else 2)
        return (bucket, (u.get("username") or ""))

    return sorted(users, key=key)

def add_user(username: str, password: str, role: str = ROLE_ADMIN) -> None:
    ensure_bootstrap_admin()
    username = (username or "").strip()
    if not username:
        raise ValueError("username is required")
    if not password:
        raise ValueError("password is required")

    role = (role or ROLE_ADMIN).strip().lower()
    if role not in ALLOWED_ROLES:
        raise ValueError("invalid role")

    data = load_web_users()
    users = data.get("users") or []
    if any((u.get("username") or "").strip() == username for u in users):
        raise ValueError("username already exists")

    users.append(
        {
            "username": username,
            "role": role,
            "password_hash": generate_password_hash(password),
            "created_at": _now_iso(),
        }
    )
    data["users"] = users
    save_web_users(data)

def delete_user(username: str) -> bool:
    ensure_bootstrap_admin()
    username = (username or "").strip()
    if not username:
        return False
    data = load_web_users()
    users = data.get("users") or []
    before = len(users)
    data["users"] = [u for u in users if (u.get("username") or "").strip() != username]
    if len(data["users"]) == before:
        return False
    save_web_users(data)
    return True

