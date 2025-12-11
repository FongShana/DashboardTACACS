from flask import Flask
from .routes.dashboard import bp as dashboard_bp
from .routes.users import bp as users_bp

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-me-in-config"

    # register blueprints
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(users_bp, url_prefix="/users")

    @app.route("/health")
    def health():
        return "OK"

    return app
