# tacacs_dashboard/routes/auth.py
from __future__ import annotations

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


