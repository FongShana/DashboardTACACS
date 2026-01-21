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
)

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
    return render_template("web_users.html", users=users, active_page="admin")


@bp.post("/admin/web-users/add")
def web_users_add():
    if not _is_superadmin():
        flash("หน้านี้สำหรับผู้ดูแลระบบ (superadmin) เท่านั้น", "error")
        return redirect(url_for("dashboard.index"))

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or ROLE_ADMIN).strip()

    try:
        add_user(username=username, password=password, role=role)
        flash(f"สร้างผู้ใช้สำหรับเข้าเว็บสำเร็จ: {username}", "success")
    except Exception as e:
        flash(f"สร้างผู้ใช้ไม่สำเร็จ: {e}", "error")
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

