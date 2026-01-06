# tacacs_dashboard/routes/terminal.py
from __future__ import annotations

from flask import Blueprint, render_template, request, jsonify

from ..services.policy_store import load_policy
from ..services.web_terminal import create_session, send_line, close_session

bp = Blueprint("terminal", __name__)

@bp.get("/terminal")
def terminal_page():
    policy = load_policy()
    devices = policy.get("devices", [])
    return render_template("terminal.html", devices=devices, active_page="terminal")

@bp.post("/terminal/connect")
def terminal_connect():
    data = request.get_json(force=True, silent=True) or {}
    device = (data.get("device") or "").strip()
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "")
    try:
        sid, role, device_ip, level, output = create_session(device, username, password)
        return jsonify({
            "ok": True,
            "session_id": sid,
            "device_ip": device_ip,
            "role": role,
            "enable_level": level,
            "output": output,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@bp.post("/terminal/send")
def terminal_send():
    data = request.get_json(force=True, silent=True) or {}
    sid = (data.get("session_id") or "").strip()
    line = data.get("line", "")
    try:
        out = send_line(sid, line)
        return jsonify({"ok": True, "output": out})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@bp.post("/terminal/close")
def terminal_close():
    data = request.get_json(force=True, silent=True) or {}
    sid = (data.get("session_id") or "").strip()
    try:
        close_session(sid)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400
