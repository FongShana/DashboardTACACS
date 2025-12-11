from flask import Blueprint, render_template

bp = Blueprint("users", __name__)

@bp.route("/")
def index():
    # dummy data
    users = [
        {"username": "eng_bkk", "roles": "OLT_ENGINEER", "status": "Active", "last_login": "2025-12-09 09:12"},
        {"username": "tech01", "roles": "OLT_OP", "status": "Active", "last_login": "2025-12-09 08:30"},
        {"username": "view01", "roles": "OLT_VIEW", "status": "Active", "last_login": "-"},
    ]

    roles = [
        {"name": "OLT_VIEW", "description": "ดู config ได้อย่างเดียว", "privilege": "1 / read-only", "members": 5},
        {"name": "OLT_OP", "description": "ปฏิบัติงานพื้นฐาน", "privilege": "15 (จำกัดคำสั่ง)", "members": 3},
        {"name": "OLT_ENGINEER", "description": "ปรับ config ระดับวิศวกร", "privilege": "15", "members": 2},
        {"name": "OLT_ADMIN", "description": "สิทธิ์เต็มบน OLT", "privilege": "15", "members": 1},
    ]

    return render_template(
        "users.html",
        users=users,
        roles=roles,
        active_page="users",
    )
