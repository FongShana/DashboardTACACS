from flask import Blueprint, render_template
from tacacs_dashboard.services.policy_store import load_policy

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
