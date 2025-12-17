from flask import Blueprint, render_template, request
from tacacs_dashboard.services.log_parser import (
    get_recent_events,
    get_user_stats,
    get_command_events,
)

bp = Blueprint("logs", __name__)


@bp.route("/")
def index():
    # ดึง event ล่าสุดจาก parser (ตอนนี้อาจยังเป็น log ตัวอย่าง)
    recent_events = get_recent_events(limit=200)
    user_stats = get_user_stats()
    command_events = get_command_events(limit=200)

    # --- อ่าน filter จาก query string ---
    user_filter = (request.args.get("user") or "").strip()
    device_filter = (request.args.get("device") or "").strip()
    result_filter = (request.args.get("result") or "").strip()

    # --- เตรียม list สำหรับ dropdown ---
    user_list = sorted({e.get("user") for e in recent_events if e.get("user")})
    device_list = sorted({e.get("device") for e in recent_events if e.get("device")})
    result_list = sorted({(e.get("result") or "").upper()
                          for e in recent_events
                          if e.get("result")})

    # --- apply filter กับ auth events ---
    filtered_events = []
    for e in recent_events:
        if user_filter and e.get("user") != user_filter:
            continue
        if device_filter and e.get("device") != device_filter:
            continue
        if result_filter and (e.get("result") or "").upper() != result_filter.upper():
            continue
        filtered_events.append(e)

    # --- สรุป stats ---
    total_events = len(filtered_events)
    total_cmd = len(command_events)

    total_success = sum(
        1 for e in filtered_events
        if (e.get("result") or "").upper() in ("ACCEPT", "OK", "PASS", "SUCCESS")
    )
    total_fail = sum(
        1 for e in filtered_events
        if (e.get("result") or "").upper() in ("REJECT", "FAIL", "ERROR")
    )

    unique_user_count = len({e.get("user") for e in filtered_events if e.get("user")})
    unique_device_count = len({e.get("device") for e in filtered_events if e.get("device")})

    return render_template(
        "logs.html",
        active_page="logs",
        # ตารางหลัก
        recent_events=filtered_events,
        command_events=command_events,
        user_stats=user_stats,
        # summary card
        total_events=total_events,
        total_cmd=total_cmd,
        total_success=total_success,
        total_fail=total_fail,
        unique_user_count=unique_user_count,
        unique_device_count=unique_device_count,
        # สำหรับ filter dropdown
        user_list=user_list,
        device_list=device_list,
        result_list=result_list,
        user_filter=user_filter,
        device_filter=device_filter,
        result_filter=result_filter,
    )

