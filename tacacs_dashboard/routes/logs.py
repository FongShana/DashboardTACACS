from flask import Blueprint, render_template, request
from tacacs_dashboard.services.log_parser import get_all_events

from tacacs_dashboard.services.log_parser import (
    get_recent_events,
    get_user_stats,
    get_command_events,
)

bp = Blueprint("logs", __name__)

@bp.route("/")
def index():
    recent_events = get_recent_events(limit=200)

    # stats ต่อ user
    user_stats = get_user_stats()

    # command logs
    command_events = get_command_events(limit=200)

    return render_template(
        "logs.html",
        active_page="logs",
        recent_events=recent_events,
        user_stats=user_stats,
        command_events=command_events,
    )

