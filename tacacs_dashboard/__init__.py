from flask import Flask
from .routes.dashboard import bp as dashboard_bp
from .routes.users import bp as users_bp
from .routes.devices import bp as devices_bp
from .routes.logs import bp as logs_bp
from .routes.settings import bp as settings_bp
from .routes.api import bp as api_bp

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-me-in-config"

    # register blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(users_bp, url_prefix="/users")
    app.register_blueprint(devices_bp, url_prefix="/devices")
    app.register_blueprint(logs_bp, url_prefix="/logs")
    app.register_blueprint(settings_bp, url_prefix="/settings")

    # register blueprint of REST API
    app.register_blueprint(api_bp, url_prefix="/api")

    @app.route("/health")
    def health():
        return "OK"

    return app
