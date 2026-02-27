#!/usr/bin/env python3
"""TACACS log SQLite indexer.

Run inside your venv, from the project root (recommended):
  /home/trainee25/tacacs-web/venv/bin/python3 tools/log_indexer.py --full

This keeps /var/log/tac_plus/*.log as the source of truth.
SQLite is only for fast search in the dashboard UI.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure the project root is importable when this file is executed directly.
# (When running a script by path, Python puts the script directory on sys.path,
# not the project root.)
BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="Index ALL log files (first run).")
    args = ap.parse_args(argv)

    # Import from project
    from tacacs_dashboard.services import log_parser
    from tacacs_dashboard.services import log_sqlite

    if not log_sqlite.is_enabled():
        print("SQLite index is disabled. Set LOG_SQLITE_ENABLED=1 in secret.env (or env) first.")
        return 2

    try:
        stats = log_sqlite.ingest_once(
            parse_authc=log_parser._parse_authc,
            parse_authz=log_parser._parse_authz,
            parse_acct=log_parser._parse_acct,
            full=bool(args.full),
        )
    except Exception as e:
        print(f"Index failed: {e}")
        return 1

    print("Index OK:", stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
