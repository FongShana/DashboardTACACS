# tacacs_dashboard/services/privilege.py
from __future__ import annotations

import re


def parse_privilege(value, *, default: int = 1) -> int:
    """Parse a privilege/enable level and clamp to 1..15.

    The UI/user may input privilege as '15', 15, '15 / full', etc.
    We extract the first integer and clamp to the valid ZTE enable range.
    """
    if value is None:
        n = int(default)
        return max(1, min(15, n))

    m = re.search(r"\d+", str(value))
    if not m:
        n = int(default)
        return max(1, min(15, n))

    n = int(m.group(0))
    return max(1, min(15, n))
