from flask import Blueprint, render_template, request
from tacacs_dashboard.services.log_parser import (
    get_recent_events,
    get_user_stats,
    get_command_events,
)

bp = Blueprint("logs", __name__)


@bp.route("/")
def index():
    # --- อ่าน filter จาก query string ---
    user_filter = (request.args.get("user") or "").strip()
    device_filter = (request.args.get("device") or "").strip()
    result_filter = (request.args.get("result") or "").strip()

    # --- command log filters ---
    cmd_user_filter = (request.args.get("cmd_user") or "").strip()
    cmd_device_filter = (request.args.get("cmd_device") or "").strip()
    cmd_contains_filter = (request.args.get("cmd_contains") or "").strip()

    # ดึง event ล่าสุดจาก parser
    recent_events = get_recent_events(limit=200)
    user_stats = get_user_stats()

    # Command audit logs:
    # - ปกติใช้ recent 200 (เร็ว)
    # - ถ้ามีการกรอง (user/device/contains) ให้ scan ทุกไฟล์ acct ที่ยังเก็บอยู่ เพื่อค้นย้อนหลัง
    scan_all_cmd = bool(cmd_user_filter or cmd_device_filter or cmd_contains_filter)
    command_events = get_command_events(
        limit=1600 if scan_all_cmd else 200,
        scan_all=scan_all_cmd,
        user=cmd_user_filter,
        device=cmd_device_filter,
        contains=cmd_contains_filter,
    )

    # --- เตรียม list สำหรับ dropdown ---
    user_list = sorted({e.get("user") for e in recent_events if e.get("user")})
    device_list = sorted({e.get("device") for e in recent_events if e.get("device")})
    result_list = sorted({(e.get("result") or "").upper()
                          for e in recent_events
                          if e.get("result")})

    cmd_user_list = sorted({e.get("user") for e in command_events if e.get("user")})
    cmd_device_list = sorted({e.get("device") for e in command_events if e.get("device")})

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

    # get_command_events() apply filters already
    filtered_cmd_events = command_events

    # --- สรุป stats ---
    total_events = len(filtered_events)
    total_cmd = len(filtered_cmd_events)

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

    cmd_unique_user_count = len({e.get("user") for e in filtered_cmd_events if e.get("user")})
    cmd_unique_device_count = len({e.get("device") for e in filtered_cmd_events if e.get("device")})

    # breakdown (top users) สำหรับ command filter
    from collections import Counter

    cmd_user_breakdown = Counter(
        (e.get("user") or "").strip() for e in filtered_cmd_events if (e.get("user") or "").strip()
    ).most_common(10)

    return render_template(
        "logs.html",
        active_page="logs",
        # ตารางหลัก
        recent_events=filtered_events,
        command_events=filtered_cmd_events,
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

        # command filter
        cmd_user_list=cmd_user_list,
        cmd_device_list=cmd_device_list,
        cmd_user_filter=cmd_user_filter,
        cmd_device_filter=cmd_device_filter,
        cmd_contains_filter=cmd_contains_filter,
        cmd_unique_user_count=cmd_unique_user_count,
        cmd_unique_device_count=cmd_unique_device_count,
        cmd_user_breakdown=cmd_user_breakdown,
    )



