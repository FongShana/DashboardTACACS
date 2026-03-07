# tacacs_dashboard/routes/auth.py
from __future__ import annotations

from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

import subprocess
from pathlib import Path

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from ..services.web_users_store import (
    ALLOWED_ROLES,
    ROLE_ADMIN,
    ROLE_SUPERADMIN,
    add_user,
    authenticate,
    delete_user,
    ensure_bootstrap_admin,
    list_users,
    get_user_record,
    get_user_device_group_ids,
    set_user_device_group_ids,
    set_user_name,
)

from ..services.device_groups_store import list_device_groups

bp = Blueprint("auth", __name__)


_BKK_TZ = ZoneInfo("Asia/Bangkok")


def _fmt_iso_to_bkk(value: str | None) -> str:
    """Format ISO-like timestamps as Asia/Bangkok time for UI display.

    Notes:
      - Stored timestamps may be naive (no tz); treat them as UTC.
      - If parsing fails, return the original string.
    """

    raw = (value or "").strip()
    if not raw:
        return ""

    try:
        iso = raw
        # Support trailing 'Z'
        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"

        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_bkk = dt.astimezone(_BKK_TZ)
        return dt_bkk.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return raw


def _is_superadmin() -> bool:
    return (session.get("web_role") or "").lower() == ROLE_SUPERADMIN


@bp.get("/login")
def login():
    # ensure there is at least one admin
    ensure_bootstrap_admin()
    if session.get("web_username"):
        return redirect(url_for("dashboard.index"))
    nxt = request.args.get("next") or ""
    return render_template("login.html", next=nxt)


@bp.post("/login")
def login_submit():
    ensure_bootstrap_admin()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    nxt = (request.form.get("next") or "").strip() or url_for("dashboard.index")

    user = authenticate(username, password)
    if not user:
        flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง", "error")
        return render_template("login.html", next=nxt), 401

    session["web_username"] = user["username"]
    role = (user.get("role") or ROLE_ADMIN).strip().lower()
    if role not in ALLOWED_ROLES:
        flash("บัญชีนี้ไม่มีสิทธิ์เข้าใช้งาน Web Dashboard", "error")
        session.pop("web_username", None)
        session.pop("web_role", None)
        return render_template("login.html", next=nxt), 403
    session["web_role"] = role
    flash(f"เข้าสู่ระบบสำเร็จ: {user['username']}", "success")
    return redirect(nxt)


@bp.get("/logout")
def logout():
    session.pop("web_username", None)
    session.pop("web_role", None)
    flash("ออกจากระบบเรียบร้อยแล้ว", "info")
    return redirect(url_for("auth.login"))


# -------------------
# Admin: Web accounts
# -------------------
@bp.get("/admin/web-users")
def web_users():
    if not _is_superadmin():
        flash("หน้านี้สำหรับผู้ดูแลระบบ (superadmin) เท่านั้น", "error")
        return redirect(url_for("dashboard.index"))
    users = list_users()
    # Display timestamps in UTC+07 (Asia/Bangkok) for consistency with other pages.
    for u in users:
        if isinstance(u, dict):
            u["created_at_bkk"] = _fmt_iso_to_bkk(u.get("created_at"))
    return render_template("web_users.html", users=users, active_page="admin_users")


@bp.post("/admin/web-users/add")
def web_users_add():
    if not _is_superadmin():
        flash("หน้านี้สำหรับผู้ดูแลระบบ (superadmin) เท่านั้น", "error")
        return redirect(url_for("dashboard.index"))

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or ROLE_ADMIN).strip()
    first_name = (request.form.get("first_name") or "").strip()
    last_name = (request.form.get("last_name") or "").strip()

    try:
        add_user(username=username, password=password, role=role, first_name=first_name, last_name=last_name)
        flash(f"สร้างผู้ใช้สำหรับเข้าเว็บสำเร็จ: {username}", "success")
    except Exception as e:
        flash(f"สร้างผู้ใช้ไม่สำเร็จ: {e}", "error")
    return redirect(url_for("auth.web_users"))


@bp.get("/admin/web-users/<username>/edit")
def web_user_edit(username: str):
    if not _is_superadmin():
        flash("หน้านี้สำหรับผู้ดูแลระบบ (superadmin) เท่านั้น", "error")
        return redirect(url_for("dashboard.index"))

    rec = get_user_record(username)
    if not rec:
        flash(f"ไม่พบบัญชีผู้ใช้: {username}", "error")
        return redirect(url_for("auth.web_users"))

    return render_template(
        "admin_web_user_edit.html",
        target_username=username,
        target_role=(rec.get("role") or ROLE_ADMIN).strip().lower(),
        first_name=(rec.get("first_name") or ""),
        last_name=(rec.get("last_name") or ""),
        active_page="admin_users",
    )


@bp.post("/admin/web-users/<username>/edit")
def web_user_edit_submit(username: str):
    if not _is_superadmin():
        flash("หน้านี้สำหรับผู้ดูแลระบบ (superadmin) เท่านั้น", "error")
        return redirect(url_for("dashboard.index"))

    rec = get_user_record(username)
    if not rec:
        flash(f"ไม่พบบัญชีผู้ใช้: {username}", "error")
        return redirect(url_for("auth.web_users"))

    first_name = (request.form.get("first_name") or "").strip()
    last_name = (request.form.get("last_name") or "").strip()

    try:
        set_user_name(username, first_name=first_name, last_name=last_name)
        flash(f"บันทึกชื่อ-นามสกุลสำหรับ {username} สำเร็จ", "success")
    except Exception as e:
        flash(f"บันทึกไม่สำเร็จ: {e}", "error")

    return redirect(url_for("auth.web_users"))


@bp.post("/admin/web-users/delete")
def web_users_delete():
    if not _is_superadmin():
        flash("หน้านี้สำหรับผู้ดูแลระบบ (superadmin) เท่านั้น", "error")
        return redirect(url_for("dashboard.index"))

    username = (request.form.get("username") or "").strip()
    if not username:
        flash("กรุณาระบุ username", "error")
        return redirect(url_for("auth.web_users"))

    if username == (session.get("web_username") or ""):
        flash("ไม่สามารถลบบัญชีที่กำลังใช้งานอยู่ได้", "error")
        return redirect(url_for("auth.web_users"))

    ok = delete_user(username)
    if ok:
        flash(f"ลบบัญชีผู้ใช้เข้าเว็บสำเร็จ: {username}", "success")
    else:
        flash(f"ไม่พบบัญชีผู้ใช้: {username}", "error")
    return redirect(url_for("auth.web_users"))


@bp.get("/admin/web-users/<username>/device-groups")
def web_user_device_groups(username: str):
    if not _is_superadmin():
        flash("หน้านี้สำหรับผู้ดูแลระบบ (superadmin) เท่านั้น", "error")
        return redirect(url_for("dashboard.index"))

    rec = get_user_record(username)
    if not rec:
        flash(f"ไม่พบบัญชีผู้ใช้: {username}", "error")
        return redirect(url_for("auth.web_users"))

    target_role = (rec.get("role") or ROLE_ADMIN).strip().lower()
    groups = list_device_groups()
    selected = set(get_user_device_group_ids(username))

    return render_template(
        "admin_user_device_groups.html",
        target_username=username,
        target_role=target_role,
        groups=groups,
        selected_group_ids=selected,
        active_page="admin_users",
    )


@bp.post("/admin/web-users/<username>/device-groups")
def web_user_device_groups_submit(username: str):
    if not _is_superadmin():
        flash("หน้านี้สำหรับผู้ดูแลระบบ (superadmin) เท่านั้น", "error")
        return redirect(url_for("dashboard.index"))

    rec = get_user_record(username)
    if not rec:
        flash(f"ไม่พบบัญชีผู้ใช้: {username}", "error")
        return redirect(url_for("auth.web_users"))

    target_role = (rec.get("role") or ROLE_ADMIN).strip().lower()
    if target_role == ROLE_SUPERADMIN:
        flash("บัญชี superadmin เข้าถึงได้ทุก group อยู่แล้ว", "info")
        return redirect(url_for("auth.web_users"))

    chosen = [(g or "").strip() for g in request.form.getlist("group_ids")]
    chosen = [g for g in chosen if g]

    # validate against current groups in policy.json
    existing = {g.get("id") for g in list_device_groups()}
    bad = [g for g in chosen if g not in existing]
    if bad:
        flash(f"มี group ที่ไม่ถูกต้อง: {', '.join(bad)}", "error")
        return redirect(url_for("auth.web_user_device_groups", username=username))

    try:
        set_user_device_group_ids(username, chosen)
        flash(f"บันทึกสิทธิ์ device groups สำหรับ {username} สำเร็จ", "success")
    except Exception as e:
        flash(f"บันทึกสิทธิ์ไม่สำเร็จ: {e}", "error")

    return redirect(url_for("auth.web_users"))



# -----------------------------
# Superadmin: Log file manager
# -----------------------------


def _fmt_bytes(n: int) -> str:
    try:
        n = int(n)
    except Exception:
        return "-"

    if n < 1024:
        return f"{n} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n = n / 1024.0
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"


def _build_page_numbers(page: int, total_pages: int, window: int = 3) -> list[int]:
    if total_pages <= 1:
        return [1]
    start = max(1, page - window)
    end = min(total_pages, page + window)
    return list(range(start, end + 1))


@bp.route("/admin/log-files", methods=["GET"])
def admin_log_files():
    # Web auth is already enforced globally; keep this as a hard authorization check.
    if not _is_superadmin():
        abort(403)

    from tacacs_dashboard.services.log_files import iter_log_files
    from tacacs_dashboard.services.log_sqlite import _env_bool

    # Feature flag (disabled by default for safety)
    delete_enabled = bool(_env_bool("LOG_FILE_DELETE_ENABLED", default=False))

    kind = (request.args.get("kind") or "").strip()
    date_from_s = (request.args.get("from") or "").strip()
    date_to_s = (request.args.get("to") or "").strip()

    d_from = None
    d_to = None
    try:
        if date_from_s:
            d_from = date.fromisoformat(date_from_s)
    except Exception:
        d_from = None
    try:
        if date_to_s:
            d_to = date.fromisoformat(date_to_s)
    except Exception:
        d_to = None

    files = list(iter_log_files())

    # Filter
    if kind in {"authc", "authz", "acct"}:
        files = [f for f in files if f.kind == kind]

    if d_from is not None:
        files = [f for f in files if f.log_date >= d_from]
    if d_to is not None:
        files = [f for f in files if f.log_date <= d_to]

    # Sort: newest date first, then kind
    files.sort(key=lambda f: (f.log_date, f.kind, f.filename), reverse=True)

    # Pagination
    try:
        page = int(request.args.get("page", "1"))
    except Exception:
        page = 1
    page = max(1, page)

    per_page = 25
    total = len(files)
    # Use integer math to avoid float rounding and extra imports
    total_pages = max(1, (total + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages

    start = (page - 1) * per_page
    end = start + per_page
    page_items = files[start:end]

    # Prepare rows for template
    rows = []
    for f in page_items:
        mtime_bkk = f.mtime_utc.astimezone(_BKK_TZ).strftime("%d/%m/%y %H:%M:%S")
        rows.append(
            {
                "filename": f.filename,
                "kind": f.kind,
                "date": f.log_date.isoformat(),
                "mtime": mtime_bkk,
                "size": _fmt_bytes(f.size_bytes),
            }
        )

    # Build page URLs while preserving filters
    base_args = {k: v for k, v in request.args.items() if k != "page" and v is not None}

    def page_url(p: int) -> str:
        args = dict(base_args)
        args["page"] = str(p)
        return url_for("auth.admin_log_files", **args)

    return render_template(
        "admin_log_files.html",
        active_page="admin_log_files",
        delete_enabled=delete_enabled,
        kind=kind,
        date_from=date_from_s,
        date_to=date_to_s,
        rows=rows,
        page=page,
        total=total,
        total_pages=total_pages,
        pages=_build_page_numbers(page, total_pages),
        page_url=page_url,
    )


@bp.route("/admin/log-files/delete", methods=["POST"])
def admin_log_files_delete():
    if not _is_superadmin():
        abort(403)

    from tacacs_dashboard.services.log_files import validate_basename
    from tacacs_dashboard.services.log_sqlite import _env_bool

    delete_enabled = bool(_env_bool("LOG_FILE_DELETE_ENABLED", default=False))
    next_url = request.form.get("next") or url_for("auth.admin_log_files")

    if not delete_enabled:
        flash("Log delete is disabled (set LOG_FILE_DELETE_ENABLED=1 in secret.env)", "error")
        return redirect(next_url)

    filename = request.form.get("filename") or ""
    confirm = (request.form.get("confirm") or "").strip()

    try:
        name = validate_basename(filename)
    except Exception:
        flash("Invalid log filename.", "error")
        return redirect(next_url)

    if confirm != "DELETE":
        flash("Please type DELETE to confirm deletion.", "error")
        return redirect(next_url)

    # Prefer sudo helper so the web process does not need write access to /var/log.
    # The helper itself enforces safe paths.
    tool_path = (Path(__file__).resolve().parents[2] / "tools" / "delete_tacacs_log.py").resolve()
    cmd = ["sudo", "-n", "/usr/bin/python3", str(tool_path), "--file", name]

    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except Exception as e:
        flash(f"Delete failed: {e}", "error")
        return redirect(next_url)

    if cp.returncode == 0:
        flash(f"Deleted {name}. (DB cleanup will be reflected after next index run)", "success")
        return redirect(next_url)

    # Common sudo failure: not allowed / password required
    out = (cp.stdout or "").strip()
    err = (cp.stderr or "").strip()
    if "password" in err.lower() or cp.returncode == 1 and "sudo" in err.lower():
        flash(
            "Delete failed: sudo is not permitted for the web user. Configure /etc/sudoers.d/tacacs-log-delete.",
            "error",
        )
    else:
        msg = err or out or f"exit={cp.returncode}"
        flash(f"Delete failed: {msg}", "error")

    return redirect(next_url)
