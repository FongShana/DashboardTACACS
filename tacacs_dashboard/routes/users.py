from flask import Blueprint, render_template, request, redirect, url_for, flash
from tacacs_dashboard.services.policy_store import load_policy, save_policy

bp = Blueprint("users", __name__)


@bp.route("/")
def index():
    policy = load_policy()
    users = policy.get("users", [])
    roles = policy.get("roles", [])

    # คำนวณจำนวน members ของแต่ละ role จาก users จริง ๆ
    user_roles = [u.get("roles") or u.get("role") for u in users]
    for r in roles:
        name = r.get("name")
        r["members"] = user_roles.count(name)

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


# -----------------------
# Roles form actions (อยู่ในหน้าเดียวกัน)
# -----------------------

@bp.post("/roles/create")
def create_role_form():
    name = request.form.get("name")
    description = request.form.get("description", "")
    privilege = request.form.get("privilege", "")

    if not name:
        flash("กรุณากรอกชื่อ Role", "error")
        return redirect(url_for("users.index"))

    policy = load_policy()
    roles = policy.get("roles", [])

    if any(r.get("name") == name for r in roles):
        flash(f"Role {name} มีอยู่แล้ว", "error")
        return redirect(url_for("users.index"))

    roles.append({
        "name": name,
        "description": description,
        "privilege": privilege,
        "members": 0,   # จะถูกคำนวณใหม่ตอน index() อยู่แล้ว
    })
    policy["roles"] = roles
    save_policy(policy)

    flash(f"เพิ่ม Role {name} เรียบร้อย", "success")
    return redirect(url_for("users.index"))


@bp.post("/roles/delete/<name>")
def delete_role_form(name):
    policy = load_policy()
    roles = policy.get("roles", [])
    users = policy.get("users", [])

    used_by = [u.get("username") for u in users
               if (u.get("roles") or u.get("role")) == name]

    if used_by:
        flash(
            f"ไม่สามารถลบ Role {name} ได้ (ถูกใช้งานโดย: {', '.join(used_by)})",
            "error"
        )
        return redirect(url_for("users.index"))

    new_roles = [r for r in roles if r.get("name") != name]
    if len(new_roles) == len(roles):
        flash(f"ไม่พบ Role {name}", "error")
        return redirect(url_for("users.index"))

    policy["roles"] = new_roles
    save_policy(policy)

    flash(f"ลบ Role {name} เรียบร้อย", "success")
    return redirect(url_for("users.index"))

@bp.get("/roles/<name>/edit")
def edit_role_form(name):
    policy = load_policy()
    roles = policy.get("roles", [])

    target = None
    for r in roles:
        if r.get("name") == name:
            target = r
            break

    if not target:
        flash(f"ไม่พบ Role {name}", "error")
        return redirect(url_for("users.index"))

    return render_template(
        "role_edit.html",
        active_page="users",
        role=target,
    )


@bp.post("/roles/<name>/edit")
def edit_role_submit(name):
    policy = load_policy()
    roles = policy.get("roles", [])

    target = None
    for r in roles:
        if r.get("name") == name:
            target = r
            break

    if not target:
        flash(f"ไม่พบ Role {name}", "error")
        return redirect(url_for("users.index"))

    # อัปเดตเฉพาะ description และ privilege
    target["description"] = request.form.get("description", "").strip()
    target["privilege"] = request.form.get("privilege", "").strip()

    save_policy(policy)
    flash(f"อัปเดต Role {name} เรียบร้อยแล้ว", "success")
    return redirect(url_for("users.index"))



@bp.get("/edit/<username>")
def edit_user_form(username):
    policy = load_policy()
    users = policy.get("users", [])
    roles = policy.get("roles", [])

    target = None
    for u in users:
        if u.get("username") == username:
            target = u
            break

    if not target:
        flash(f"ไม่พบผู้ใช้ {username}", "error")
        return redirect(url_for("users.index"))

    # role ปัจจุบันของ user (รองรับทั้ง 'roles' และ 'role')
    current_role = target.get("roles") or target.get("role") or ""

    return render_template(
        "user_edit.html",
        active_page="users",
        user=target,
        roles=roles,
        current_role=current_role,
    )


@bp.post("/edit/<username>")
def edit_user_submit(username):
    policy = load_policy()
    users = policy.get("users", [])
    roles = policy.get("roles", [])

    target = None
    for u in users:
        if u.get("username") == username:
            target = u
            break

    if not target:
        flash(f"ไม่พบผู้ใช้ {username}", "error")
        return redirect(url_for("users.index"))

    new_role = (request.form.get("role") or "").strip()
    new_status = (request.form.get("status") or "").strip()

    # ตรวจว่า role ใหม่มีอยู่จริงไหม
    role_names = {r.get("name") for r in roles}
    if new_role and new_role not in role_names:
        flash(f"Role {new_role} ไม่มีอยู่ในระบบ", "error")
        return redirect(url_for("users.edit_user_form", username=username))

    # อัปเดตค่า (ใช้ key 'roles' เป็นหลัก)
    target["roles"] = new_role
    target["status"] = new_status or target.get("status", "Active")

    save_policy(policy)
    flash(f"อัปเดตผู้ใช้ {username} เรียบร้อยแล้ว", "success")
    return redirect(url_for("users.index"))
