from flask import Blueprint, render_template

bp = Blueprint("settings", __name__)

@bp.route("/")
def index():
    # Example; Change to be able to pull from config in the future
    settings = {
        "tacacs_config_path": "/etc/tac_plus-ng.cfg",
        "tacacs_log_path": "/var/log/tac_plus-ng.acct",
        "web_listen": "0.0.0.0:8080",
    }

    return render_template(
        "settings.html",
        settings=settings,
        active_page="settings",
    )
