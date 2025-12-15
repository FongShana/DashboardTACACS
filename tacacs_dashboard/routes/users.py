from flask import Blueprint, render_template, request, redirect, url_for, flash
from tacacs_dashboard.services.policy_store import load_policy, save_policy

bp = Blueprint("users", __name__)

@bp.route("/")
def index():
    
    policy = load_policy()
    users = policy.get("users", [])
    roles = policy.get("roles", [])

    return render_template(
        "users.html",
        users=users,
        roles=roles,
        active_page="users",
    )

@bp.post("/create")
def create_user_form():
    username = request.form.get("username")
    role = request.form.get("role")
    status = request.form.get("status", "Active")

    if not username or not role:
        flash("กรุณากรอก Username และ Role ให้ครบ", "error")
        return redirect(url_for("users.index"))

    policy = load_policy()
    users = policy.get("users", [])
    roles = policy.get("roles", [])
    role_names = {r.get("name") for r in roles}

    if role not in role_names:
        flash(f"Role {role} ไม่มีอยู่ในระบบ", "error")
        return redirect(url_for("users.index"))

    if any(u.get("username") == username for u in users):
        flash(f"User {username} มีอยู่แล้ว", "error")
        return redirect(url_for("users.index"))

    users.append({
        "username": username,
        "roles": role,
        "status": status,
        "last_login": "-"
    })
    policy["users"] = users
    save_policy(policy)

    flash(f"เพิ่มผู้ใช้ {username} เรียบร้อย", "success")
    return redirect(url_for("users.index"))

@bp.post("/delete/<username>")
def delete_user_form(username):
    policy = load_policy()
    users = policy.get("users", [])
    new_users = [u for u in users if u.get("username") != username]

    if len(new_users) == len(users):
        flash(f"ไม่พบผู้ใช้ {username}", "error")
        return redirect(url_for("users.index"))

    policy["users"] = new_users
    save_policy(policy)

    flash(f"ลบผู้ใช้ {username} เรียบร้อย", "success")
    return redirect(url_for("users.index"))
