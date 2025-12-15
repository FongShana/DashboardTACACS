from flask import Blueprint, render_template
from tacacs_dashboard.services.policy_store import load_policy

bp = Blueprint("devices", __name__)

@bp.route("/")
def index():
    policy = load_policy()
    devices = policy.get("devices", [])

    return render_template(
        "devices.html",
        devices=devices,
        active_page="devices",
    )
