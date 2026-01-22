from __future__ import annotations

from typing import Dict, List

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from ..services.policy_store import load_policy
from ..services.web_users_store import ROLE_SUPERADMIN
from ..services.device_groups_store import delete_device_group, list_device_groups, upsert_device_group

bp = Blueprint("device_groups", __name__)


def _require_superadmin() -> bool:
    return (session.get("web_role") or "").strip().lower() == ROLE_SUPERADMIN


@bp.get("/")
def index():
    if not _require_superadmin():
        flash("หน้านี้สำหรับผู้ดูแลระบบ (superadmin) เท่านั้น", "error")
        return redirect(url_for("dashboard.index"))

    policy = load_policy()
    devices = policy.get("devices", []) or []
    groups = list_device_groups()

    # count devices per group
    counts: Dict[str, int] = {}
    for d in devices:
        if isinstance(d, dict):
            gid = (d.get("group_id") or "").strip()
            if gid:
                counts[gid] = counts.get(gid, 0) + 1

    return render_template(
        "device_groups.html",
        groups=groups,
        counts=counts,
        active_page="admin_groups",
    )


@bp.post("/add")
def add_group():
    if not _require_superadmin():
        flash("หน้านี้สำหรับผู้ดูแลระบบ (superadmin) เท่านั้น", "error")
        return redirect(url_for("dashboard.index"))

    group_id = (request.form.get("group_id") or "").strip()
    name = (request.form.get("name") or "").strip()

    try:
        created = upsert_device_group(group_id, name)
        if created:
            flash(f"สร้าง Group สำเร็จ: {group_id}", "success")
        else:
            flash(f"อัปเดต Group สำเร็จ: {group_id}", "success")
    except Exception as e:
        flash(f"สร้าง/อัปเดต Group ไม่สำเร็จ: {e}", "error")

    return redirect(url_for("device_groups.index"))


@bp.post("/delete")
def delete_group():
    if not _require_superadmin():
        flash("หน้านี้สำหรับผู้ดูแลระบบ (superadmin) เท่านั้น", "error")
        return redirect(url_for("dashboard.index"))

    group_id = (request.form.get("group_id") or "").strip()
    try:
        delete_device_group(group_id)
        flash(f"ลบ Group สำเร็จ: {group_id}", "success")
    except Exception as e:
        flash(f"ลบ Group ไม่สำเร็จ: {e}", "error")

    return redirect(url_for("device_groups.index"))
