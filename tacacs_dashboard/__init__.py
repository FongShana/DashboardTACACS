import os

from flask import Flask, redirect, request, session, url_for

from .routes.dashboard import bp as dashboard_bp
from .routes.users import bp as users_bp
from .routes.devices import bp as devices_bp
from .routes.logs import bp as logs_bp
from .routes.api import bp as api_bp
from .routes.terminal import bp as terminal_bp
from .routes.auth import bp as auth_bp


def _is_public_endpoint(endpoint: str | None) -> bool:
    if not endpoint:
        return True
    if endpoint.startswith("static"):
        return True
    # auth + health are public
    if endpoint.startswith("auth."):
        return True
    if endpoint == "health":
        return True
    return False

def create_app():
    app = Flask(__name__)
    # Use env in production: DASHBOARD_SECRET_KEY
    app.config["SECRET_KEY"] = os.getenv("DASHBOARD_SECRET_KEY", "change-me-in-config")

    # register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(users_bp, url_prefix="/users")
    app.register_blueprint(devices_bp, url_prefix="/devices")
    app.register_blueprint(logs_bp, url_prefix="/logs")

    # register blueprint of REST API
    app.register_blueprint(api_bp, url_prefix="/api")

    # web terminal
    app.register_blueprint(terminal_bp)

    @app.route("/health")
    def health():
        return "OK"

    # -------------------------
    # Simple session-based auth
    # -------------------------
    @app.before_request
    def require_login():
        if _is_public_endpoint(request.endpoint):
            return None

        # Require login for everything else (UI + API)
        if not session.get("web_username"):
            nxt = request.path
            return redirect(url_for("auth.login", next=nxt))
        return None

    @app.context_processor
    def inject_current_user():
        username = session.get("web_username")
        role = (session.get("web_role") or "admin").strip().lower()
        return {
            "current_user": username,
            "current_role": role,
            "is_superadmin": role == "superadmin",
        }

    return app


