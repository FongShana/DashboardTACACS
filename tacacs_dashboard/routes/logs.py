from flask import Blueprint, render_template

bp = Blueprint("logs", __name__)

@bp.route("/")
def index():
    # ตัวอย่าง log dummy
    events = [
        {"time": "2025-12-09 09:12", "user": "eng_bkk", "role": "OLT_ENGINEER",
         "device": "OLT_ZTE_BTG1", "action": "login", "result": "success"},
        {"time": "2025-12-09 09:08", "user": "eng_bkk", "role": "OLT_ENGINEER",
         "device": "OLT_ZTE_BTG1", "action": "command: ont reset 1 1", "result": "success"},
        {"time": "2025-12-09 08:55", "user": "guest01", "role": "-", "device": "OLT_HW_SITEA",
         "action": "login", "result": "failed"},
    ]

    return render_template(
        "logs.html",
        events=events,
        active_page="logs",
    )
