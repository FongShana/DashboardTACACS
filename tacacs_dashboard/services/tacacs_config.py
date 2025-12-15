from .policy_store import load_policy

def build_config_text():
    policy = load_policy()
    lines = []
    lines.append("id = nt-tacacs {")
    lines.append("  # devices")
    for dev in policy.get("devices", []):
        lines.append(f"  device {dev['name']} {{")
        lines.append(f"    address = {dev['ip']}")
        lines.append("    key = SECRETKEY   # TODO: แยกไปเก็บที่อื่น")
        lines.append("  }")
        lines.append("")

    lines.append("  # Users")
    for user in policy.get("users", []):
        username = user.get("username", "unknown")
        # รองรับทั้ง 'role' และ 'roles'
        role = user.get("role") or user.get("roles") or "UNASSIGNED"

        lines.append(f"  user {username} {{")
        lines.append("    # password = (configured separately)")
        lines.append(f"    member = {role}")
        lines.append("  }")
        lines.append("")

    lines.append("  # Roles (as groups) - conceptual")
    for role in policy.get("roles", []):
        lines.append(f"  group {role['name']} {{")
        lines.append(f"    # privilege: {role['privilege']}")
        lines.append(f"    # description: {role['description']}")
        lines.append("  }")
        lines.append("")

    lines.append("}")
    return "\n".join(lines)
