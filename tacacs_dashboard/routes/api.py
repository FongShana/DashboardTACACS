from flask import Blueprint, jsonify, request
from tacacs_dashboard.services.log_parser import get_recent_events, get_summary, get_all_events

bp = Blueprint("api", __name__)

@bp.get("/summary")
def api_summary():
    """
    Give back summarize data as Dashboard as JSON
    Ex. active_users, failed_logins, devices, roles
    """
    summary = get_summary()
    return jsonify(summary)


@bp.get("/logs")
def api_logs():
    """
    Give back log as JSON
    Support query string ?limit=20
    """
    limit = request.args.get("limit", default=50, type=int)
    events = get_recent_events(limit=limit)
    return jsonify(events)


@bp.get("/logs/all")
def api_logs_all():
    """
    See all log (from sample file right now)
    Be careful that real log maybe too big
    """
    events = get_all_events()
    return jsonify(events)
