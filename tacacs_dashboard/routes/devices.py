from flask import Blueprint, render_template

bp = Blueprint("devices", __name__)

@bp.route("/")
def index():
    devices = [
        {"name": "OLT_ZTE_1", "vendor": "ZTE", "ip": "10.235.110.10", "site": "BTG", "status": "Online"},
        {"name": "OLT_ZTE_2", "vendor": "ZTE", "ip": "10.235.110.11", "site": "BTG", "status": "Online"},
        {"name": "OLT_HW_1", "vendor": "Huawei", "ip": "192.168.99.10", "site": "SITE-A", "status": "Unknown"},
    ]

    return render_template(
        "devices.html",
        devices=devices,
        active_page="devices",
    )
