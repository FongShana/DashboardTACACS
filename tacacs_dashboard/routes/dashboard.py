from flask import Blueprint, render_template
from tacacs_dashboard.services.log_parser import get_recent_events, get_summary

bp = Blueprint("dashboard", __name__)

@bp.route("/")
def index():
    summary = get_summary()
    events = get_recent_events(limit=10)
    # No inormation yet, just template for now
    return render_template(
        "dashboard.html",
        summary=summary,
        events=events,
        active_page="dashboard"
)
