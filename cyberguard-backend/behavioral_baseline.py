import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from typing import Any


def parse_login_event(payload: str) -> dict[str, Any] | None:
    try:
        event = json.loads(payload)
    except (TypeError, json.JSONDecodeError):
        return None
    return event if isinstance(event, dict) else None


def baseline_key(event: Mapping[str, Any], actor: str) -> str:
    account = next((event.get(key) for key in ("account_id", "user_id", "username", "email") if event.get(key)), actor)
    identity = f"{actor.strip().lower()}:{str(account).strip().lower()[:180]}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def login_sample(event: Mapping[str, Any]) -> dict[str, Any]:
    country_value = event.get("country") or event.get("location_country")
    country = str(country_value).strip().upper()[:64] if country_value else None
    device_value = event.get("device_id") or event.get("device")
    device = hashlib.sha256(str(device_value).strip().lower().encode("utf-8")).hexdigest() if device_value else None
    hour_value = event.get("hour")
    hour = hour_value if isinstance(hour_value, int) and not isinstance(hour_value, bool) and 0 <= hour_value <= 23 else None
    if hour is None and isinstance(event.get("timestamp"), str):
        try:
            hour = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).hour
        except ValueError:
            hour = None
    return {"country": country, "device": device, "hour": hour}


def successful_login(event: Mapping[str, Any]) -> bool:
    status = str(event.get("event_type", event.get("status", ""))).strip().lower()
    success = event.get("success") is True or str(event.get("success", "")).lower() in {"true", "1"}
    return success or status in {"success", "login_success", "successful_login", "authentication_success"}


def score_login_deviation(sample: Mapping[str, Any], history: list[Mapping[str, Any]]) -> tuple[int, list[str], list[dict[str, Any]]]:
    if len(history) < 3:
        return 0, [], []
    score = 0
    reasons = []
    indicators = []
    for key, weight, label in (("country", 20, "Unfamiliar Login Country"), ("device", 25, "Unfamiliar Login Device")):
        value = sample.get(key)
        known = {item.get(key) for item in history if item.get(key)}
        if value and known and value not in known:
            score += weight
            reasons.append(f"Login used a {key} not seen in this account's recent successful-login baseline.")
            indicators.append({"name": label, "weight": weight})
    hour = sample.get("hour")
    known_hours = [item.get("hour") for item in history if isinstance(item.get("hour"), int)]
    if isinstance(hour, int) and known_hours:
        nearest_delta = min(min(abs(hour - known), 24 - abs(hour - known)) for known in known_hours)
        if nearest_delta >= 4:
            score += 15
            reasons.append("Login hour is outside the account's recent successful-login pattern.")
            indicators.append({"name": "Unusual Login Hour", "weight": 15})
    return score, reasons, indicators