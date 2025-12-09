from flask import Blueprint, render_template

bp = Blueprint("dashboard", __name__)

@bp.route("/")
def index():
    # No inormation yet, just template for now
    return render_template("dashboard.html")
