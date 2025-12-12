from flask import Blueprint, render_template
from tacacs_dashboard.services.log_parser import get_all_events

bp = Blueprint("logs", __name__)

@bp.route("/")
def index():
    events = get_all_events()
    return render_template(
        "logs.html",
        events=events,
        active_page="logs",
    )

