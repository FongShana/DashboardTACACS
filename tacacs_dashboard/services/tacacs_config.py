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

    lines.append("  # users")
    for user in policy.get("users", []):
        lines.append(f"  user {user['username']} {{")
        lines.append("    # password จะไปจัดการทีหลัง")
        lines.append(f"    member = {user['role']}")
        lines.append("  }")
        lines.append("")

    lines.append("}")
    return "\n".join(lines)
