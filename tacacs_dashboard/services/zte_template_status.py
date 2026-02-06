# -*- coding: utf-8 -*-
"""ZTE local system-user template status probe (C600/TITAN) - block-accurate.

Fixes the two issues you observed:
1) Wrong value like "Template 2128"
   - Caused by matching global AAA binds (aaa-authentication-template 2128) instead of
     the *system-user user-name zte* block.
   - This version only extracts bind templates that are INSIDE the `user-name <target>`
     block (indent-based parsing).

2) Some OLTs show Unknown while others work
   - Often caused by output truncation or slow/large running-config.
   - This version tries smaller, targeted commands first (begin/section) and falls back
     to full running-config with larger capture cap and longer timeout.

Env knobs (optional) in secret.env:
  ZTE_TEMPLATE_CACHE_TTL=20
  ZTE_TEMPLATE_TIMEOUT=10          # base timeout seconds
  ZTE_TEMPLATE_TIMEOUT_FULL=25     # timeout for full running-config
  ZTE_TEMPLATE_USER=zte
  ZTE_TEMPLATE_FULL_MAX_CHARS=2000000

Credentials:
  - Prefer OLT_PROVISION_USER / OLT_PROVISION_PASSWORD
  - Fallback to OLT_ADMIN_USER / OLT_ADMIN_PASSWORD (or OLT_ADMIN_PASS)
"""

import re
import time
from dataclasses import dataclass
from typing import Dict, Tuple, Optional, List

from .locks import exclusive_lock
from .tacacs_config import _read_env
from .olt_telnet import telnet_exec_commands

_CACHE = {}  # type: Dict[str, Tuple[float, "ZteTemplateStatus"]]

# -------- regex (strict, line-based) --------
_RE_USER_LINE = re.compile(r'(?i)^\s*(?:system-user\s+)?user-name\s+("?)(\S+)\1\b')
_RE_BIND_AUTH = re.compile(r'(?i)^\s*bind\s+(?:aaa-)?authentication-template\s+(\d+)\b')
_RE_BIND_AUTHOR = re.compile(r'(?i)^\s*bind\s+(?:aaa-)?authorization-template\s+(\d+)\b')


@dataclass
class ZteTemplateStatus:
    template: str  # "128", "1", "unknown", "mismatch"
    auth_template: str = ""
    author_template: str = ""
    note: str = ""  # safe hint for debugging (no secrets)


def _as_float(v, default):
    try:
        return float(v)
    except Exception:
        return default


def _as_int(v, default):
    try:
        return int(v)
    except Exception:
        return default


def _list_creds_to_try():
    creds = []  # type: List[Tuple[str, str, str]]

    prov_user = (_read_env("OLT_PROVISION_USER", "") or "").strip()
    prov_pass = (_read_env("OLT_PROVISION_PASSWORD", "") or "").strip()
    if prov_user and prov_pass:
        creds.append((prov_user, prov_pass, "provision"))

    admin_user = (_read_env("OLT_ADMIN_USER", "zte") or "zte").strip()
    admin_pass = ((_read_env("OLT_ADMIN_PASS", "") or "") or (_read_env("OLT_ADMIN_PASSWORD", "") or "")).strip()
    if admin_user and admin_pass:
        if (not creds) or (admin_user != creds[0][0] or admin_pass != creds[0][1]):
            creds.append((admin_user, admin_pass, "admin"))

    return creds


def _indent(s):
    if not s:
        return 0
    # count leading spaces/tabs as "indent"
    return len(s) - len(s.lstrip(" \t"))


def _parse_user_block(text, target_user):
    """Parse template binds from *inside* the user-name block (indent-based)."""
    if not text:
        return ZteTemplateStatus(template="unknown", note="empty output")

    tgt = (target_user or "zte").strip().strip('"').lower()
    lines = (text or "").splitlines()

    idx = None
    base_indent = 0
    for i, raw in enumerate(lines):
        m = _RE_USER_LINE.match(raw or "")
        if not m:
            continue
        uname = (m.group(2) or "").strip().strip('"').lower()
        if uname == tgt:
            idx = i
            base_indent = _indent(raw)
            break

    if idx is None:
        return ZteTemplateStatus(template="unknown", note="user-name not found")

    auth = ""
    author = ""

    # scan forward until next user-name with indent <= base_indent OR section end
    for j in range(idx + 1, len(lines)):
        line = lines[j] or ""
        if not line.strip():
            continue

        ind = _indent(line)
        # leaving the block
        if ind <= base_indent:
            # next user-name begins
            if _RE_USER_LINE.match(line):
                break
            # common section separators / new top-level sections
            if line.lstrip().startswith(("!", "<", "aaa", "interface", "pon", "gpon", "end")):
                break
            # otherwise, still treat as end-of-block
            break

        m1 = _RE_BIND_AUTH.match(line)
        if m1:
            auth = m1.group(1) or auth
            continue
        m2 = _RE_BIND_AUTHOR.match(line)
        if m2:
            author = m2.group(1) or author
            continue

    if not auth and not author:
        return ZteTemplateStatus(template="unknown", note="user found but no bind lines inside block")

    if auth and author and auth != author:
        return ZteTemplateStatus(template="mismatch", auth_template=auth, author_template=author, note="auth != author")

    tpl = auth or author or "unknown"
    return ZteTemplateStatus(template=tpl, auth_template=auth, author_template=author)


def _run(ip, user, pw, enable15, timeout_s, cmd, max_chars):
    return telnet_exec_commands(
        host=ip,
        admin_user=user,
        admin_pass=pw,
        enable_pass=enable15,
        commands=[cmd],
        timeout=timeout_s,
        debug=False,
        max_output_chars=max_chars,
    ) or ""


def _probe_with_cmds(ip, user, pw, label, target_user, enable15, timeout_s, timeout_full, full_max_chars):
    """Try targeted commands first, then full running-config."""
    # Targeted (if supported by this OLT)
    candidates = [
        "show running-config | begin user-name " + target_user,
        "show running-config | begin system-user",
        "show running-config | section system-user",
    ]

    last_note = ""
    for cmd in candidates:
        try:
            out = _run(ip, user, pw, enable15, timeout_s, cmd, max_chars=200000)
            st = _parse_user_block(out, target_user)
            if st.template != "unknown":
                st.note = st.note or ("ok via %s: %s" % (label, cmd))
                return st
            last_note = st.note or "unknown"
        except Exception as e:
            # Many CLIs print "Invalid" => olt_telnet raises RuntimeError; treat as unsupported and continue
            last_note = ("%s: %s" % (cmd, str(e)[:120]))

    # Full fallback (more reliable but larger)
    try:
        out_full = _run(ip, user, pw, enable15, timeout_full, "show running-config", max_chars=full_max_chars)
        st2 = _parse_user_block(out_full, target_user)
        st2.note = st2.note or ("via %s/full" % label)
        if st2.template == "unknown" and last_note:
            st2.note = (st2.note + " | last: " + last_note)[:200]
        return st2
    except Exception as e:
        return ZteTemplateStatus(template="unknown", note=("%s/full: %s" % (label, str(e)[:140])))


def get_zte_template_status(ip):
    ip = (ip or "").strip()
    if not ip:
        return ZteTemplateStatus(template="unknown", note="empty ip")

    ttl = _as_float(_read_env("ZTE_TEMPLATE_CACHE_TTL", "20") or "20", 20.0)
    now = time.time()

    cached = _CACHE.get(ip)
    if cached is not None:
        ts, st = cached
        if (now - ts) <= ttl:
            return st

    lock_name = "zte_tpl_" + ip.replace(".", "_")
    with exclusive_lock(lock_name, timeout_sec=25.0):
        cached2 = _CACHE.get(ip)
        now2 = time.time()
        if cached2 is not None:
            ts2, st2 = cached2
            if (now2 - ts2) <= ttl:
                return st2

        creds = _list_creds_to_try()
        if not creds:
            st = ZteTemplateStatus(template="unknown", note="OLT login creds not configured")
            _CACHE[ip] = (time.time(), st)
            return st

        target_user = (_read_env("ZTE_TEMPLATE_USER", "zte") or "zte").strip()
        timeout_s = _as_int((_read_env("ZTE_TEMPLATE_TIMEOUT", _read_env("OLT_TELNET_TIMEOUT", "10") or "10") or "10"), 10)
        timeout_full = _as_int((_read_env("ZTE_TEMPLATE_TIMEOUT_FULL", "25") or "25"), 25)
        enable15 = (_read_env("OLT_ENABLE15_PASSWORD", "") or "").strip()
        full_max_chars = _as_int((_read_env("ZTE_TEMPLATE_FULL_MAX_CHARS", "2000000") or "2000000"), 2000000)

        last = None  # type: Optional[ZteTemplateStatus]

        for user, pw, label in creds:
            st = _probe_with_cmds(
                ip=ip,
                user=user,
                pw=pw,
                label=label,
                target_user=target_user,
                enable15=enable15,
                timeout_s=timeout_s,
                timeout_full=max(timeout_full, timeout_s),
                full_max_chars=full_max_chars,
            )
            if st.template != "unknown":
                _CACHE[ip] = (time.time(), st)
                return st
            last = st

        st_final = last or ZteTemplateStatus(template="unknown", note="unknown")
        _CACHE[ip] = (time.time(), st_final)
        return st_final


def template_label(st):
    """Human label for UI."""
    t = (getattr(st, "template", "") or "").strip().lower()
    if t == "128":
        return "Template 128"
    if t == "1":
        return "Template 1"
    if t == "mismatch":
        a = (getattr(st, "auth_template", "") or "?")
        b = (getattr(st, "author_template", "") or "?")
        return "Mismatch (auth %s / author %s)" % (a, b)
    if t and t != "unknown":
        return "Template %s" % getattr(st, "template", "")
    return "Unknown"
