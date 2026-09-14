from datetime import datetime, timedelta, timezone
from typing import Any


def build_timeline(incident: dict[str, Any]) -> list[dict[str, Any]]:
    created = datetime.fromisoformat(incident["created_at"].replace("Z", "+00:00")) if incident.get("created_at") else datetime.now(timezone.utc)
    risk = incident.get("risk_score", 0)
    steps = [("signal", "Signal observed", "Telemetry entered the detection pipeline"), ("triage", "AI triage", "Risk indicators and IOCs were scored"), ("correlation", "Campaign correlation", "Threat genome compared against recent incidents"), ("response", "Response recommendation", "Containment sequence prepared")]
    return [{"id": index + 1, "type": kind, "label": label, "detail": detail, "timestamp": (created + timedelta(minutes=index * 3)).isoformat(), "status": "complete" if index < 2 or risk > 70 else "pending"} for index, (kind, label, detail) in enumerate(steps)]