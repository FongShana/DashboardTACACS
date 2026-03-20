# tacacs_dashboard/services/user_secrets_store.py
from __future__ import annotations

import json
import os
import secrets
import string
import subprocess
from pathlib import Path
from typing import Dict, Any, Tuple

from .locks import exclusive_lock

BASE_DIR = Path(__file__).resolve().parent.parent.parent
SECRET_ENV_PATH = BASE_DIR / "secret.env"
DEFAULT_SECRETS_PATH = BASE_DIR / "user_secrets.json"


PasswordSpec = Tuple[str, str]  # (kind, value)


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


def get_user_secrets_path() -> Path:
    return _secrets_path()


def _default_password_from_env() -> str:
    return _read_env("DEFAULT_USER_PASSWORD")


def _default_hash_scheme() -> str:
    scheme = (_read_env("USER_PASSWORD_HASH_SCHEME", "crypt") or "crypt").strip().lower()
    return scheme if scheme in {"clear", "crypt", "pbkdf2"} else "crypt"


def _hash_password_crypt_sha512(password: str) -> str:
    password = (password or "").strip()
    if not password:
        raise ValueError("password is required")

    # Preferred path on Linux/Python versions that still ship the stdlib crypt module.
    try:  # pragma: no cover - platform dependent
        import crypt

        salt = crypt.mksalt(crypt.METHOD_SHA512)
        hashed = crypt.crypt(password, salt)
        if hashed:
            return hashed
    except Exception:
        pass

    # Fallback for platforms / Python builds without the crypt module (e.g. newer Python).
    salt_alphabet = string.ascii_letters + string.digits + './'
    salt = ''.join(secrets.choice(salt_alphabet) for _ in range(16))
    try:
        r = subprocess.run(
            ['/usr/bin/openssl', 'passwd', '-6', '-salt', salt, password],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception as e:  # pragma: no cover - platform dependent
        raise RuntimeError(f"failed to generate crypt hash via openssl: {e}") from e

    hashed = (r.stdout or '').strip()
    if r.returncode != 0 or not hashed:
        err = (r.stderr or r.stdout or '').strip() or 'openssl passwd failed'
        raise RuntimeError(f"failed to generate crypt hash: {err}")
    return hashed


def _hash_password(password: str, scheme: str | None = None) -> PasswordSpec:
    scheme = (scheme or _default_hash_scheme() or "crypt").strip().lower()
    password = (password or "").strip()
    if not password:
        raise ValueError("password is required")

    if scheme == "clear":
        return ("clear", password)

    if scheme == "pbkdf2":
        # NOTE:
        # The current project is kept dependency-light. Generating tac_plus-ng-compatible
        # PBKDF2 strings without an extra dependency is less portable than using crypt(3).
        # We therefore fall back to crypt SHA-512 for storage unless the file already
        # contains a pbkdf2 hash from a prior migration/manual input.
        scheme = "crypt"

    return ("crypt", _hash_password_crypt_sha512(password))


def _spec_to_storage_dict(kind: str, value: str, *, is_default: bool = False) -> Dict[str, str]:
    if is_default:
        if kind == "clear":
            return {"default_password": value}
        return {
            "default_password_type": kind,
            "default_password_hash": value,
        }

    if kind == "clear":
        return {"password": value}
    return {
        "password_type": kind,
        "password_hash": value,
    }


def _default_password_spec_from_data(data: Dict[str, Any]) -> PasswordSpec:
    kind = (data.get("default_password_type") or data.get("default_password_kind") or "").strip().lower()
    value = (
        data.get("default_password_hash")
        or data.get("default_password_value")
        or ""
    )
    value = (value or "").strip()
    if kind and value:
        return (kind, value)

    pw = (data.get("default_password") or "").strip()
    if pw:
        return ("clear", pw)

    pw = (_default_password_from_env() or "").strip()
    if pw:
        return ("clear", pw)

    return ("clear", "")


def _user_password_spec_from_entry(entry: Dict[str, Any] | None) -> PasswordSpec:
    if not isinstance(entry, dict):
        return ("", "")

    kind = (entry.get("password_type") or entry.get("password_kind") or "").strip().lower()
    value = (entry.get("password_hash") or entry.get("password_value") or "").strip()
    if kind and value:
        return (kind, value)

    pw = (entry.get("password") or "").strip()
    if pw:
        return ("clear", pw)

    return ("", "")


def _normalize_secrets_payload(data: Dict[str, Any], *, hash_cleartext: bool) -> Dict[str, Any]:
    src = data if isinstance(data, dict) else {}
    out: Dict[str, Any] = {"users": {}}

    # Root/default password
    def_kind, def_value = _default_password_spec_from_data(src)
    if def_kind == "clear" and def_value and hash_cleartext:
        def_kind, def_value = _hash_password(def_value)
    out.update(_spec_to_storage_dict(def_kind, def_value, is_default=True))

    # Users
    users = src.get("users") or {}
    if isinstance(users, dict):
        for username, entry in users.items():
            uname = (username or "").strip()
            if not uname:
                continue
            kind, value = _user_password_spec_from_entry(entry if isinstance(entry, dict) else {})
            if not value:
                continue
            if kind == "clear" and hash_cleartext:
                kind, value = _hash_password(value)
            out["users"][uname] = _spec_to_storage_dict(kind, value, is_default=False)

    return out


def load_user_secrets() -> Dict[str, Any]:
    path = _secrets_path()
    if not path.exists():
        return {"default_password": _default_password_from_env(), "users": {}}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_user_secrets(data: Dict[str, Any]) -> None:
    """Atomic write (tmp -> replace). Caller is responsible for locking.

    Any clear-text passwords present in `data` are converted to the configured
    on-disk format before the file is written.
    """
    path = _secrets_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")

    normalized = _normalize_secrets_payload(data, hash_cleartext=True)

    with tmp.open("w", encoding="utf-8") as f:
        json.dump(normalized, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def get_default_password() -> str:
    """Backward-compatible helper.

    Returns the default password *value* as stored. For hashed storage this is
    the hash string, not the original clear-text password.
    """
    kind, value = get_default_password_spec()
    return value


def get_default_password_spec() -> PasswordSpec:
    s = load_user_secrets()
    kind, value = _default_password_spec_from_data(s)
    if value:
        return (kind or "clear", value)
    return ("clear", "")


def set_user_password(username: str, password: str) -> None:
    username = (username or "").strip()
    password = (password or "").strip()
    if not username:
        raise ValueError("username is required")
    if not password:
        raise ValueError("password is required")

    kind, value = _hash_password(password)

    with exclusive_lock("user_secrets"):
        s = load_user_secrets()
        s.setdefault("users", {})
        s["users"].setdefault(username, {})
        s["users"][username] = _spec_to_storage_dict(kind, value, is_default=False)
        save_user_secrets(s)


def get_user_password(username: str) -> str:
    """Backward-compatible helper returning only the stored value portion."""
    _kind, value = get_user_password_spec(username)
    return value


def get_user_password_spec(username: str) -> PasswordSpec:
    username = (username or "").strip()
    s = load_user_secrets()
    users = s.get("users") or {}
    u = users.get(username) or {}
    kind, value = _user_password_spec_from_entry(u)
    if value:
        return (kind or "clear", value)
    return get_default_password_spec()


def ensure_user_has_password(username: str) -> None:
    username = (username or "").strip()
    if not username:
        return

    with exclusive_lock("user_secrets"):
        s = load_user_secrets()
        s.setdefault("users", {})
        if username not in s["users"]:
            def_kind, def_value = get_default_password_spec()
            if not def_value:
                raise ValueError("default password is not configured")
            s["users"][username] = _spec_to_storage_dict(def_kind, def_value, is_default=False)
            save_user_secrets(s)


def delete_user_password(username: str) -> None:
    username = (username or "").strip()

    with exclusive_lock("user_secrets"):
        s = load_user_secrets()
        users = s.get("users") or {}
        if username in users:
            users.pop(username, None)
            s["users"] = users
            save_user_secrets(s)


def migrate_user_secrets_to_hashed() -> Dict[str, Any]:
    """One-time migration helper: convert clear-text entries in user_secrets.json
    to hashed entries.

    Returns a small summary dict.
    """
    with exclusive_lock("user_secrets"):
        path = _secrets_path()
        before = load_user_secrets()
        after = _normalize_secrets_payload(before, hash_cleartext=True)
        changed = json.dumps(before, ensure_ascii=False, sort_keys=True) != json.dumps(after, ensure_ascii=False, sort_keys=True)
        if changed:
            save_user_secrets(after)
        return {
            "path": str(path),
            "changed": changed,
            "default_password_type": (after.get("default_password_type") or ("clear" if after.get("default_password") else "")),
            "user_count": len(after.get("users") or {}),
        }
