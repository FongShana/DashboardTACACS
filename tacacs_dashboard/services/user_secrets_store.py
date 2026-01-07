# tacacs_dashboard/services/user_secrets_store.py
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Any

BASE_DIR = Path(__file__).resolve().parent.parent.parent
SECRET_ENV_PATH = BASE_DIR / "secret.env"
DEFAULT_SECRETS_PATH = BASE_DIR / "user_secrets.json"


def _read_env(key: str, default: str = "") -> str:
    if not SECRET_ENV_PATH.exists():
        return default
    for line in SECRET_ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return default


def _secrets_path() -> Path:
    p = (_read_env("USER_SECRETS_JSON", "") or "").strip()
    return Path(p) if p else DEFAULT_SECRETS_PATH


def _default_password_from_env() -> str:
    return _read_env("DEFAULT_USER_PASSWORD", "test") or "test"


def load_user_secrets() -> Dict[str, Any]:
    path = _secrets_path()
    if not path.exists():
        return {"default_password": _default_password_from_env(), "users": {}}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_user_secrets(data: Dict[str, Any]) -> None:
    path = _secrets_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def get_default_password() -> str:
    s = load_user_secrets()
    pw = (s.get("default_password") or "").strip()
    return pw or _default_password_from_env()


def get_user_password(username: str) -> str:
    username = (username or "").strip()
    s = load_user_secrets()
    users = s.get("users") or {}
    u = users.get(username) or {}
    pw = (u.get("password") or "").strip()
    return pw or get_default_password()


def ensure_user_has_password(username: str) -> None:
    username = (username or "").strip()
    if not username:
        return
    s = load_user_secrets()
    s.setdefault("users", {})
    if username not in s["users"]:
        s["users"][username] = {"password": get_default_password()}
        save_user_secrets(s)


def delete_user_password(username: str) -> None:
    username = (username or "").strip()
    s = load_user_secrets()
    users = s.get("users") or {}
    if username in users:
        users.pop(username, None)
        s["users"] = users
        save_user_secrets(s)

