"""OLT reachability/status probe helpers.

Goal: provide a lightweight Online/Offline indicator for OLTs without storing
status in policy.json.

Default method: TCP connect probe (no secrets required).

Optional secret.env knobs (all optional):
  OLT_STATUS_METHOD=tcp|ping      # default: tcp
  OLT_STATUS_PORT=23             # default: 23 (telnet)
  OLT_STATUS_TIMEOUT=1.2         # seconds
  OLT_STATUS_CACHE_TTL=15        # seconds

Notes:
- "online" here means: target is reachable via the chosen probe.
- For strict/real health, you'd do an authenticated command (heavier + secrets).
"""

from __future__ import annotations

import socket
import subprocess
import time
from typing import Dict, Tuple

from .tacacs_config import _read_env


# ip -> (timestamp, status)
_CACHE: Dict[str, Tuple[float, str]] = {}


def _as_float(v: str, default: float) -> float:
    try:
        return float(v)
    except Exception:
        return default


def _as_int(v: str, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _tcp_probe(ip: str, port: int, timeout_s: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def _ping_probe(ip: str, timeout_s: float) -> bool:
    """ICMP ping probe.

    Caveats:
    - Some environments block ICMP.
    - ping binary/capabilities may vary.

    Returns True if at least 1 echo reply is received.
    """
    # Use Linux ping semantics: -c 1 = one packet, -W = timeout in seconds
    timeout_i = max(1, int(timeout_s))
    try:
        r = subprocess.run(
            ["/bin/ping", "-c", "1", "-W", str(timeout_i), ip],
            capture_output=True,
            text=True,
            timeout=timeout_i + 1,
        )
        return r.returncode == 0
    except Exception:
        return False


def get_olt_status(ip: str) -> str:
    """Return one of: 'online', 'offline', 'unknown'.

    Uses cached result within TTL.
    """
    ip = (ip or "").strip()
    if not ip:
        return "unknown"

    now = time.time()
    ttl = _as_float(_read_env("OLT_STATUS_CACHE_TTL", "15") or "15", 15.0)

    cached = _CACHE.get(ip)
    if cached is not None:
        ts, st = cached
        if (now - ts) <= ttl:
            return st

    method = (_read_env("OLT_STATUS_METHOD", "tcp") or "tcp").strip().lower()
    timeout_s = _as_float(_read_env("OLT_STATUS_TIMEOUT", "1.2") or "1.2", 1.2)

    st = "offline"
    try:
        if method == "ping":
            st = "online" if _ping_probe(ip, timeout_s) else "offline"
        else:
            port = _as_int(_read_env("OLT_STATUS_PORT", "23") or "23", 23)
            st = "online" if _tcp_probe(ip, port, timeout_s) else "offline"
    except Exception:
        st = "unknown"

    _CACHE[ip] = (now, st)
    return st


def status_label(st: str) -> str:
    """Pretty label for UI."""
    s = (st or "").strip().lower()
    if s == "online":
        return "Online"
    if s == "offline":
        return "Offline"
    return "Unknown"
