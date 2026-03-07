"""Admin utilities for managing TACACS+ log files on disk.

This module is intentionally conservative:
- Only files inside /var/log/tac_plus
- Only daily log filenames: authc/authz/acct-YYYY-MM-DD.log
- No symlinks

Deletion is typically executed via a sudo-approved helper script (see tools/delete_tacacs_log.py)
so the web process (non-root) doesn't need write access to /var/log.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


LOG_DIR = Path("/var/log/tac_plus")

# Keep this in sync with tac_plus-ng daily file naming used in this project.
_LOG_RE = re.compile(r"^(authc|authz|acct)-(\d{4}-\d{2}-\d{2})\.log$")


@dataclass(frozen=True)
class LogFileInfo:
    filename: str
    kind: str
    log_date: date
    size_bytes: int
    mtime_utc: datetime


def _parse_filename(name: str) -> Optional[tuple[str, date]]:
    m = _LOG_RE.match(name)
    if not m:
        return None
    kind = m.group(1)
    d = date.fromisoformat(m.group(2))
    return kind, d


def iter_log_files() -> Iterable[LogFileInfo]:
    """Yield LogFileInfo for eligible log files under LOG_DIR."""
    try:
        base = LOG_DIR.resolve()
    except FileNotFoundError:
        return

    if not base.exists() or not base.is_dir():
        return

    for p in base.iterdir():
        if not p.is_file():
            continue
        if p.is_symlink():
            continue

        parsed = _parse_filename(p.name)
        if not parsed:
            continue
        kind, d = parsed

        try:
            st = p.stat()
        except FileNotFoundError:
            continue

        mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
        yield LogFileInfo(
            filename=p.name,
            kind=kind,
            log_date=d,
            size_bytes=int(st.st_size),
            mtime_utc=mtime,
        )


def validate_basename(filename: str) -> str:
    """Validate and normalize a user-supplied filename (must be basename)."""
    name = (filename or "").strip()
    if not name or ("/" in name) or ("\\" in name):
        raise ValueError("invalid filename")
    if not _parse_filename(name):
        raise ValueError("unsupported log filename")
    return name


def resolve_log_path(filename: str) -> Path:
    """Resolve a validated basename into an absolute Path within LOG_DIR."""
    name = validate_basename(filename)
    base = LOG_DIR.resolve()
    p = (base / name).resolve()
    # Ensure path stays inside LOG_DIR
    base_str = str(base) + os.sep
    if not str(p).startswith(base_str):
        raise ValueError("path traversal detected")
    if p.is_symlink():
        raise ValueError("symlink not allowed")
    return p


def delete_log_file(filename: str) -> None:
    """Delete a log file on disk.

    NOTE: This requires OS permissions to delete files in /var/log/tac_plus.
    In production, prefer running this via a sudo-approved helper.
    """
    p = resolve_log_path(filename)
    if not p.exists():
        raise FileNotFoundError(filename)
    p.unlink()
