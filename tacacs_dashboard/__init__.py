from flask import Flask
from .routes.dashboard import bp as dashboard_bp

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-me-in-config"

    # register blueprints
    app.register_blueprint(dashboard_bp)

    @app.route("/health")
    def health():
        return "OK"

    return app
