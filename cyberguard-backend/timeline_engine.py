from datetime import datetime
from typing import Any

_TIMELINE_TYPES = {
    "incident_created",
    "analysis_completed",
    "campaign_correlated",
    "workflow_updated",
    "response_action",
}


def build_timeline(
    incident: dict[str, Any],
    events: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return only persisted events with real timestamps; never synthesize steps."""
    del incident
    normalized = []
    for event in events or []:
        if not isinstance(event, dict) or event.get("type") not in _TIMELINE_TYPES:
            continue
        timestamp = event.get("timestamp")
        if not isinstance(timestamp, str):
            continue
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        normalized.append(
            {
                "type": event["type"],
                "label": str(event.get("label", event["type"].replace("_", " ").title())),
                "detail": str(event.get("detail", "")),
                "timestamp": parsed.isoformat(),
                "status": str(event.get("status", "complete")),
            }
        )
    normalized.sort(key=lambda event: event["timestamp"])
    return [{"id": index, **event} for index, event in enumerate(normalized, start=1)]
