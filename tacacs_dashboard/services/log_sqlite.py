# tacacs_dashboard/services/log_sqlite.py
from __future__ import annotations


"""SQLite-backed log index for fast log browsing/search in the dashboard.

Key idea:
  - Keep /var/log/tac_plus/*.log as the audit source of truth.
  - Maintain a SQLite index as a read-optimized cache so the web UI doesn't have to
    repeatedly scan many log files.

Safety/concurrency:
  - Uses fcntl lock files via services.locks.exclusive_lock so only one process
    writes to the SQLite DB at a time (safe under multi-worker Gunicorn).
  - DB uses WAL mode to allow concurrent readers while one writer runs.

Configuration:
  - LOG_SQLITE_ENABLED=1|0   (default: 0)
  - LOG_SQLITE_PATH=/path/to/db.sqlite3 (default: <BASE_DIR>/data/tacacs_logs.sqlite3)
  - LOG_SQLITE_RETENTION_DAYS=90 (default: 90)
  - LOG_SQLITE_WEB_MAX_FILES=8   (default: 8)   # per pattern, for the web "quick ingest"
  - LOG_SQLITE_MIN_INTERVAL_SEC=2 (default: 2)  # per-process ingest throttle

NOTE: We intentionally read config from secret.env (like your TACACS generator)
      so you don't have to modify systemd Environment= lines.
"""

import os
import sqlite3
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

# Display timezone for UI (keep UTC+07 but hide "+0700")
_DISPLAY_TZ = ZoneInfo("Asia/Bangkok")

def _format_ts(ts: float) -> str:
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc).astimezone(_DISPLAY_TZ)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""

from pathlib import Path
from typing import Callable, Optional

from .locks import exclusive_lock

# Keep consistent with services/log_parser.py
LOG_DIR = Path("/var/log/tac_plus")

# Project root (policy.json, secret.env live here)
BASE_DIR = Path(__file__).resolve().parent.parent.parent
SECRET_ENV_PATH = BASE_DIR / "secret.env"


def _read_env(key: str, default: str = "") -> str:
    """Read key from (1) process env then (2) secret.env then fallback default."""
    v = os.getenv(key)
    if v is not None and str(v).strip() != "":
        return str(v).strip()

    if not SECRET_ENV_PATH.exists():
        return default

    try:
        for line in SECRET_ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
    except Exception:
        return default

    return default


def _env_bool(key: str, default: bool = False) -> bool:
    v = (_read_env(key, "1" if default else "0") or "").strip().lower()
    return v in ("1", "true", "yes", "y", "on")


def _env_int(key: str, default: int) -> int:
    try:
        return int((_read_env(key, str(default)) or str(default)).strip())
    except Exception:
        return int(default)


def is_enabled() -> bool:
    return _env_bool("LOG_SQLITE_ENABLED", default=False)


def db_path() -> Path:
    p = _read_env("LOG_SQLITE_PATH", str(BASE_DIR / "data" / "tacacs_logs.sqlite3"))
    return Path(p).expanduser()


def _connect() -> sqlite3.Connection:
    p = db_path()
    p.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        str(p),
        timeout=30,
        isolation_level=None,  # autocommit; we manage transactions explicitly
        check_same_thread=False,
    )

    # WAL enables concurrent readers + one writer
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA foreign_keys=ON;")
    except Exception:
        pass

    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
          id       INTEGER PRIMARY KEY AUTOINCREMENT,
          ts       REAL NOT NULL,
          time_str TEXT,
          source   TEXT,
          file     TEXT,
          user     TEXT,
          device   TEXT,
          action   TEXT,
          result   TEXT,
          command  TEXT,
          raw      TEXT
        );
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ingest_state (
          file       TEXT PRIMARY KEY,
          source     TEXT,
          inode      INTEGER,
          size       INTEGER,
          mtime      REAL,
          offset     INTEGER,
          updated_at REAL
        );
        """
    )

    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_user_ts ON events(user, ts DESC);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_device_ts ON events(device, ts DESC);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ts ON events(source, ts DESC);")


def _list_files(pattern: str, *, max_files: Optional[int] = None) -> list[Path]:
    if not LOG_DIR.exists():
        return []

    files = sorted(LOG_DIR.glob(pattern), key=lambda x: x.stat().st_mtime, reverse=True)
    if max_files is not None and max_files > 0:
        return files[: int(max_files)]
    return files


def _load_state(conn: sqlite3.Connection, file: Path) -> dict:
    row = conn.execute(
        "SELECT file, inode, size, mtime, offset FROM ingest_state WHERE file = ?",
        (str(file),),
    ).fetchone()
    if not row:
        return {"inode": None, "size": 0, "mtime": 0.0, "offset": 0}
    return {"inode": row[1], "size": row[2] or 0, "mtime": row[3] or 0.0, "offset": row[4] or 0}


def _save_state(conn: sqlite3.Connection, file: Path, *, source: str, inode: int, size: int, mtime: float, offset: int) -> None:
    conn.execute(
        """
        INSERT INTO ingest_state(file, source, inode, size, mtime, offset, updated_at)
        VALUES(?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(file) DO UPDATE SET
          source=excluded.source,
          inode=excluded.inode,
          size=excluded.size,
          mtime=excluded.mtime,
          offset=excluded.offset,
          updated_at=excluded.updated_at
        """,
        (str(file), source, int(inode), int(size), float(mtime), int(offset), float(time.time())),
    )


def _retention_cleanup(conn: sqlite3.Connection) -> None:
    days = _env_int("LOG_SQLITE_RETENTION_DAYS", 90)
    if days <= 0:
        return
    cutoff = time.time() - (days * 86400)
    try:
        conn.execute("DELETE FROM events WHERE ts < ?", (float(cutoff),))
    except Exception:
        return


def _missing_file_cleanup(conn: sqlite3.Connection) -> dict:
    """Remove rows for log files that no longer exist on disk.

    Why:
      - The SQLite DB is a cache for fast browsing.
      - Raw log files in /var/log/tac_plus may be rotated/removed.
      - Without cleanup, the UI can show historical rows for files that no
        longer exist, which can confuse operators.

    Safety:
      - Only considers file paths that resolve under LOG_DIR.
      - Runs only in "full" (indexer) mode so it won't add latency to web requests.

    Returns:
      {"files": <int>, "rows": <int>}
    """

    try:
        base = LOG_DIR.resolve()
    except Exception:
        return {"files": 0, "rows": 0}

    candidates: set[str] = set()

    # ingest_state is authoritative for what we have indexed per file.
    try:
        for (f,) in conn.execute("SELECT DISTINCT file FROM ingest_state").fetchall():
            if f:
                candidates.add(str(f))
    except Exception:
        pass

    # Also consider any file values that may exist in events (extra safety).
    try:
        for (f,) in conn.execute(
            "SELECT DISTINCT file FROM events WHERE file IS NOT NULL AND file != ''"
        ).fetchall():
            if f:
                candidates.add(str(f))
    except Exception:
        pass

    missing: list[str] = []
    for fstr in sorted(candidates):
        try:
            p = Path(fstr)
            if not p.is_absolute():
                p = LOG_DIR / p

            # Resolve without requiring the target to exist.
            try:
                rp = p.resolve(strict=False)
            except TypeError:
                # Older Python compatibility (shouldn't happen on Ubuntu 22.04).
                rp = p.resolve()

            # Only delete rows for files under LOG_DIR.
            if not (str(rp).startswith(str(base) + os.sep) or str(rp) == str(base)):
                continue

            if not rp.exists():
                missing.append(fstr)
        except Exception:
            continue

    removed_files = 0
    removed_rows = 0
    for fstr in missing:
        try:
            c = conn.execute("SELECT COUNT(*) FROM events WHERE file = ?", (fstr,)).fetchone()
            if c and c[0]:
                removed_rows += int(c[0])

            conn.execute("DELETE FROM events WHERE file = ?", (fstr,))
            conn.execute("DELETE FROM ingest_state WHERE file = ?", (fstr,))
            removed_files += 1
        except Exception:
            continue

    return {"files": int(removed_files), "rows": int(removed_rows)}


def ingest_once(
    *,
    parse_authc: Callable[[str], Optional[dict]],
    parse_authz: Callable[[str], Optional[dict]],
    parse_acct: Callable[[str], Optional[dict]],
    parse_conn: Optional[Callable[[str], Optional[dict]]] = None,
    full: bool = False,
) -> dict:
    """Incrementally ingest logs into SQLite.

    - full=False (web-safe): ingest only latest N files per type (configurable)
    - full=True  (indexer mode): ingest ALL matching files

    Returns a small stats dict (no secrets).
    """

    if not is_enabled():
        return {"enabled": False, "ingested": 0, "files": 0}

    max_files = None if full else _env_int("LOG_SQLITE_WEB_MAX_FILES", 8)

    sources: list[tuple[str, str, Callable[[str], Optional[dict]]]] = [
        ("authc", "authc-*.log", parse_authc),
        ("authz", "authz-*.log", parse_authz),
        ("acct", "acct-*.log", parse_acct),
    ]

    if parse_conn is not None:
        sources.append(("conn", "conn-*.log", parse_conn))

    ingested_rows = 0
    file_count = 0
    cleanup_stats = {"files": 0, "rows": 0}

    conn = _connect()
    try:
        # One transaction for the whole ingest pass
        conn.execute("BEGIN")

        for source, pattern, parse_fn in sources:
            files = _list_files(pattern, max_files=max_files)
            for p in files:
                file_count += 1
                ingested_rows += _ingest_one_file(conn, p, source=source, parse_fn=parse_fn)

        _retention_cleanup(conn)

        # In full/indexer mode, keep DB consistent with the current on-disk logs.
        if full:
            cleanup_stats = _missing_file_cleanup(conn)
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass

    out = {"enabled": True, "ingested": int(ingested_rows), "files": int(file_count), "full": bool(full)}
    if full:
        out["cleanup_missing_files"] = cleanup_stats
    return out


def _ingest_one_file(
    conn: sqlite3.Connection,
    file: Path,
    *,
    source: str,
    parse_fn: Callable[[str], Optional[dict]],
) -> int:
    try:
        st = file.stat()
    except OSError:
        return 0

    inode = int(getattr(st, "st_ino", 0) or 0)
    size = int(st.st_size)
    mtime = float(st.st_mtime)

    state = _load_state(conn, file)
    offset = int(state.get("offset") or 0)

    # Rotation/truncation safety
    if state.get("inode") and int(state.get("inode") or 0) != inode:
        # inode changed => treat as new file content
        conn.execute("DELETE FROM events WHERE file = ?", (str(file),))
        offset = 0
    if size < offset:
        # truncated
        conn.execute("DELETE FROM events WHERE file = ?", (str(file),))
        offset = 0

    rows: list[tuple] = []
    new_offset = offset

    # Read from offset (binary) and decode line-by-line
    try:
        with file.open("rb") as f:
            f.seek(offset)
            for raw_b in f:
                try:
                    line = raw_b.decode("utf-8", errors="ignore").rstrip("\n")
                except Exception:
                    continue
                if not line.strip():
                    continue

                e = parse_fn(line)
                if not e:
                    continue

                ts = float(e.get("_ts") or 0.0)
                time_str = (e.get("time") or e.get("timestamp") or "").strip()

                user = (e.get("user") or "").strip()
                device = (e.get("device") or "").strip()
                action = (e.get("action") or "").strip()
                result = (e.get("result") or "").strip()
                command = (e.get("command") or "").strip()
                raw = (e.get("raw") or e.get("msg") or "").strip() or (line.strip())

                # Keep rows small-ish, but don't hard-truncate silently.
                rows.append(
                    (
                        ts,
                        time_str,
                        source,
                        str(file),
                        user,
                        device,
                        action,
                        result,
                        command,
                        raw,
                    )
                )

            new_offset = int(f.tell())
    except Exception:
        return 0

    if rows:
        conn.executemany(
            """
            INSERT INTO events(ts, time_str, source, file, user, device, action, result, command, raw)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    _save_state(conn, file, source=source, inode=inode, size=size, mtime=mtime, offset=new_offset)
    return len(rows)


# -----------------------------
# Web-safe "maybe ingest" API
# -----------------------------

_LAST_INGEST_AT: float = 0.0


def maybe_ingest_quick(
    *,
    parse_authc: Callable[[str], Optional[dict]],
    parse_authz: Callable[[str], Optional[dict]],
    parse_acct: Callable[[str], Optional[dict]],
    parse_conn: Optional[Callable[[str], Optional[dict]]] = None,
) -> None:
    """Best-effort quick ingest used by web requests.

    - throttled per-process (default 2s)
    - uses a short lock timeout; if another process is ingesting, we skip
    """

    global _LAST_INGEST_AT

    if not is_enabled():
        return

    min_interval = float(_env_int("LOG_SQLITE_MIN_INTERVAL_SEC", 2))
    now = time.time()
    if (now - float(_LAST_INGEST_AT or 0.0)) < min_interval:
        return

    # Try to avoid blocking the web request.
    try:
        with exclusive_lock("log_sqlite", timeout_sec=0.15, poll_sec=0.03):
            # Re-check after waiting for lock
            now2 = time.time()
            if (now2 - float(_LAST_INGEST_AT or 0.0)) < min_interval:
                return
            ingest_once(
                parse_authc=parse_authc,
                parse_authz=parse_authz,
                parse_acct=parse_acct,
                parse_conn=parse_conn,
                full=False,
            )
            _LAST_INGEST_AT = time.time()
    except TimeoutError:
        # Another worker is ingesting; skip.
        return
    except Exception:
        # Never break the web page because indexing failed.
        return


# -----------------------------
# Query helpers
# -----------------------------



def query_recent_events(
    limit: int = 200,
    *,
    start_ts: float | None = None,
    end_ts: float | None = None,
    user: str = "",
    device: str = "",
    result: str = "",
) -> list[dict]:
    """Return recent auth/session events for Logs/Auth page."""
    if not is_enabled():
        return []

    u = (user or "").strip()
    d = (device or "").strip()
    r = (result or "").strip()

    where = ["source IN ('authc','authz','acct')"]
    params: list = []

    if start_ts is not None:
        where.append("ts >= ?")
        params.append(float(start_ts))
    if end_ts is not None:
        where.append("ts < ?")
        params.append(float(end_ts))

    if u:
        where.append("user = ?")
        params.append(u)
    if d:
        where.append("device = ?")
        params.append(d)
    if r:
        where.append("UPPER(result) = UPPER(?)")
        params.append(r)

    sql = (
        "SELECT ts, time_str, user, device, action, result, raw, command "
        "FROM events WHERE "
        + " AND ".join(where)
        + " ORDER BY ts DESC LIMIT ?"
    )
    params.append(int(max(0, limit)))

    conn = _connect()
    try:
        rows = conn.execute(sql, tuple(params)).fetchall()
    finally:
        try:
            conn.close()
        except Exception:
            pass

    out: list[dict] = []
    for ts, time_str, user, device, action, result, raw, command in rows:
        disp = _format_ts(ts)
        e = {
            "time": disp,
            "timestamp": disp,
            "user": user or "",
            "device": device or "",
            "action": action or "",
            "result": result or "",
            "raw": raw or "",
            "_ts": float(ts or 0.0),
        }
        if command:
            e["command"] = command
        out.append(e)

    # match file-parser behavior: strip _ts before returning
    out.sort(key=lambda x: x.get("_ts", 0.0), reverse=True)
    for e in out:
        e.pop("_ts", None)
    return out


def query_command_events(
    limit: int = 200,
    *,
    user: str = "",
    device: str = "",
    contains: str = "",
    start_ts: float | None = None,
    end_ts: float | None = None,
) -> list[dict]:
    """Return command audit events from indexed acct logs."""

    if not is_enabled():
        return []

    u = (user or "").strip()
    d = (device or "").strip()
    needle = (contains or "").strip().lower()

    where = ["(command IS NOT NULL AND command != '')"]
    params: list = []

    if start_ts is not None:
        where.append("ts >= ?")
        params.append(float(start_ts))
    if end_ts is not None:
        where.append("ts < ?")
        params.append(float(end_ts))

    if u:
        where.append("user = ?")
        params.append(u)
    if d:
        where.append("device = ?")
        params.append(d)
    if needle:
        where.append("(LOWER(command) LIKE ? OR LOWER(raw) LIKE ?)")
        like = f"%{needle}%"
        params.extend([like, like])

    sql = (
        "SELECT ts, time_str, user, device, action, result, raw, command "
        "FROM events WHERE "
        + " AND ".join(where)
        + " ORDER BY ts DESC LIMIT ?"
    )
    params.append(int(max(0, limit)))

    conn = _connect()
    try:
        rows = conn.execute(sql, tuple(params)).fetchall()
    finally:
        try:
            conn.close()
        except Exception:
            pass

    out: list[dict] = []
    for ts, time_str, user, device, action, result, raw, command in rows:
        disp = _format_ts(ts)
        e = {
            "time": disp,
            "timestamp": disp,
            "user": user or "",
            "device": device or "",
            "action": "command",  # keep UI consistent with old parser
            "result": result or "",
            "raw": raw or "",
            "command": command or "",
            "_ts": float(ts or 0.0),
        }
        out.append(e)

    out.sort(key=lambda x: x.get("_ts", 0.0), reverse=True)
    for e in out:
        e.pop("_ts", None)
    return out

def query_last_login_map(*, successful_only: bool = True) -> dict[str, str]:
    """Return {user: time_str} for last successful login."""
    if not is_enabled():
        return {}

    where = ["source='authc'", "action='login'"]
    params: list = []

    if successful_only:
        where.append("UPPER(result) IN ('ACCEPT','OK','SUCCESS','PASS')")

    conn = _connect()
    try:
        sql = (
            """
            SELECT user, time_str
            FROM events e
            JOIN (
              SELECT user AS u, MAX(ts) AS mx
              FROM events
              WHERE """
            + " AND ".join(where)
            + """
              GROUP BY user
            ) t ON e.user = t.u AND e.ts = t.mx
            WHERE e.user IS NOT NULL AND e.user != ''
            """
        )
        rows = conn.execute(sql, tuple(params)).fetchall()
    except Exception:
        rows = []
    finally:
        try:
            conn.close()
        except Exception:
            pass

    out: dict[str, str] = {}
    for user, time_str in rows:
        if user:
            out[str(user)] = str(time_str or "")
    return out
