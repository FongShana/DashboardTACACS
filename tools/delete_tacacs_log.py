#!/usr/bin/env python3
"""Delete a TACACS log file safely.

This script is intentionally **stdlib-only** so it can be executed with the
system Python (e.g. via sudo) without requiring the project's virtualenv.

Safety rules:
- Only allow deleting files inside /var/log/tac_plus
- Only allow expected daily log names: authc-YYYY-MM-DD.log, authz-YYYY-MM-DD.log, acct-YYYY-MM-DD.log
- Reject any path traversal or unexpected filenames
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

LOG_DIR = Path("/var/log/tac_plus").resolve()
NAME_RE = re.compile(r"^(authc|authz|acct)-\d{4}-\d{2}-\d{2}\.log$")


def _safe_target(filename: str) -> Path:
    # reject any path components
    if "/" in filename or "\\" in filename:
        raise ValueError("Invalid filename")
    if not NAME_RE.match(filename):
        raise ValueError("Filename not allowed")
    p = (LOG_DIR / filename).resolve()

    # ensure it is inside LOG_DIR
    base = str(LOG_DIR)
    ps = str(p)
    if ps != base and not ps.startswith(base + os.sep):
        raise ValueError("Path traversal detected")
    return p


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True, help="Filename to delete (e.g. acct-2026-02-01.log)")
    args = ap.parse_args(argv)

    try:
        target = _safe_target(args.file)
    except Exception as e:
        print(f"ERROR: {e}")
        return 2

    if not target.exists():
        print("ERROR: file not found")
        return 3

    try:
        target.unlink()
    except PermissionError:
        print("ERROR: permission denied (need sudo)")
        return 4
    except Exception as e:
        print(f"ERROR: delete failed: {e}")
        return 5

    print(f"OK: deleted {target.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
