from pathlib import Path
from typing import Any

import yaml

ALLOWED_ACTIONS = {"block_domain", "quarantine", "revoke_session", "notify_soc", "escalate", "warn_user"}
PLAYBOOK_DIR = Path(__file__).with_name("playbooks")


def validate_playbook(document: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(document, dict) or not isinstance(document.get("id"), str) or not isinstance(document.get("trigger"), dict):
        raise ValueError("Playbook requires id and trigger fields")
    actions = document.get("actions")
    if not isinstance(actions, list) or not actions or any(action not in ALLOWED_ACTIONS for action in actions):
        raise ValueError(f"actions must be a non-empty list from {sorted(ALLOWED_ACTIONS)}")
    return {"id": document["id"], "name": str(document.get("name", document["id"])), "trigger": document["trigger"], "actions": actions, "approval_required": bool(document.get("approval_required", True))}


def load_playbooks() -> list[dict[str, Any]]:
    PLAYBOOK_DIR.mkdir(exist_ok=True)
    results = []
    for path in sorted(PLAYBOOK_DIR.glob("*.y*ml")):
        with path.open("r", encoding="utf-8") as handle:
            results.append(validate_playbook(yaml.safe_load(handle)))
    return results


def plan_playbook(playbook: dict[str, Any], assessment: dict[str, Any], approved: bool = False) -> dict[str, Any]:
    playbook = validate_playbook(playbook)
    matches = assessment.get("risk_level", "Safe").lower() == str(playbook["trigger"].get("risk_level", "")).lower()
    return {"playbook_id": playbook["id"], "matched": matches, "approval_required": playbook["approval_required"], "approved": approved, "actions": playbook["actions"] if matches else [], "mode": "execute" if matches and approved else "dry-run"}
