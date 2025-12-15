import json
import os

POLICY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "policy.json"
)

def load_policy():
    if not os.path.exists(POLICY_PATH):
        return {"users": [], "roles": [], "devices": []}
    with open(POLICY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_policy(data):
    with open(POLICY_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
