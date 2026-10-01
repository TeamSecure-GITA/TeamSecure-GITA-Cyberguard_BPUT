"""Deterministic data-loss prevention signals for submitted telemetry."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any, Iterator

_CARD_NUMBER = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_AADHAAR_NUMBER = re.compile(r"(?<!\d)[2-9]\d{11}(?!\d)")
_PAN_NUMBER = re.compile(r"(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])", re.IGNORECASE)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_KNOWN_TOKEN = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,})\b"
)
_LABELED_SECRET = re.compile(
    r"\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret)\b"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{12,})",
    re.IGNORECASE,
)
_ARCHIVE_TERMS = ("archive", "compress", "zip", "tar", "rar")
_UPLOAD_TERMS = ("upload", "egress", "exfil", "outbound", "transfer")
_PERSONAL_CLOUD_HOSTS = (
    "drive.google.com",
    "dropbox.com",
    "onedrive.live.com",
    "box.com",
    "mega.nz",
)


def _walk_strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    stack = [(value, path)]
    visited = 0
    while stack and visited < 2_000:
        current, current_path = stack.pop()
        visited += 1
        if isinstance(current, dict):
            stack.extend((child, str(key).lower()) for key, child in current.items())
        elif isinstance(current, list):
            stack.extend((child, current_path) for child in current)
        elif isinstance(current, str):
            yield current_path, current[:250_000]


def _luhn_valid(number: str) -> bool:
    digits = [int(character) for character in number if character.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _sensitive_data_findings(value: Any) -> list[tuple[str, int]]:
    findings: list[tuple[str, int]] = []
    for field, text in _walk_strings(value):
        if field:
            text = f"{field}={text}"
        card_count = sum(1 for match in _CARD_NUMBER.finditer(text) if _luhn_valid(match.group()))
        if card_count:
            findings.append(("Payment Card Data", card_count))
        aadhaar_count = len(_AADHAAR_NUMBER.findall(text))
        if aadhaar_count:
            findings.append(("Aadhaar-like Identifier", aadhaar_count))
        pan_count = len(_PAN_NUMBER.findall(text))
        if pan_count:
            findings.append(("PAN-like Identifier", pan_count))
        private_key_count = len(_PRIVATE_KEY.findall(text))
        token_count = len(_KNOWN_TOKEN.findall(text))
        labeled_count = len(_LABELED_SECRET.findall(text))
        secret_count = private_key_count + token_count + labeled_count
        if secret_count:
            findings.append(("Credential or Private-Key Material", secret_count))
    return findings


def _records(document: Any) -> list[dict[str, Any]]:
    if isinstance(document, list):
        values = document
    elif isinstance(document, dict):
        values = document.get("flows", document.get("events", [document]))
    else:
        values = []
    if isinstance(values, dict):
        values = [values]
    return [record for record in values if isinstance(record, dict)] if isinstance(values, list) else []


def _is_egress(record: dict[str, Any]) -> bool:
    direction = str(record.get("direction", record.get("network_direction", ""))).lower()
    if any(term in direction for term in ("outbound", "egress", "upload", "exfil", "send", "tx")):
        return True
    if _number(record, "bytes_out", "bytes_sent", "bytes_tx", "upload_bytes") > 0:
        return True
    activity = " ".join(
        str(record.get(key, ""))
        for key in ("event_type", "action", "operation", "command")
    ).lower()
    return any(term in activity for term in _UPLOAD_TERMS)


def _number(record: dict[str, Any], *keys: str) -> float:
    for key in keys:
        try:
            value = float(record.get(key, 0) or 0)
        except (TypeError, ValueError):
            continue
        if value >= 0 and value < float("inf"):
            return value
    return 0.0


def _is_off_hours(record: dict[str, Any]) -> bool:
    value = record.get("off_hours")
    if isinstance(value, bool):
        return value
    timestamp = record.get("timestamp")
    if not isinstance(timestamp, str):
        return False
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    utc_hour = parsed.astimezone(timezone.utc).hour
    return utc_hour < 6 or utc_hour >= 22


def analyze_dlp(payload: str | dict[str, Any] | list[Any]) -> dict[str, Any]:
    """Score sensitive-data egress and supporting exfiltration behavior."""
    try:
        document = json.loads(payload) if isinstance(payload, str) else payload
    except json.JSONDecodeError:
        document = payload

    records = _records(document)
    evidence: list[tuple[str, str, int]] = []
    score = 0

    has_event_container = isinstance(document, list) or (
        isinstance(document, dict)
        and any(isinstance(document.get(key), (dict, list)) for key in ("events", "flows"))
    )
    sensitive_source = (
        [record for record in records if _is_egress(record)]
        if has_event_container
        else document
    )
    for finding, count in _sensitive_data_findings(sensitive_source):
        weight = min(45, 30 + (count - 1) * 5)
        evidence.append((finding, f"Submitted exfiltration telemetry contains {count} sensitive-data indicator(s).", weight))
        score += weight

    total_egress = sum(
        _number(record, "bytes_out", "bytes_sent", "bytes_tx", "upload_bytes")
        for record in records
    )
    if total_egress >= 50_000_000:
        evidence.append(("Large Egress Volume", f"Observed outbound transfer is {int(total_egress)} bytes.", 25))
        score += 25

    baseline_triggered = False
    rare_destination_triggered = False
    off_hours_triggered = False
    personal_cloud_triggered = False
    for record in records:
        bytes_out = _number(record, "bytes_out", "bytes_sent", "bytes_tx", "upload_bytes")
        baseline = _number(record, "user_baseline_bytes_out", "baseline_bytes_out")
        if baseline >= 1_000_000 and bytes_out >= 10_000_000 and bytes_out >= baseline * 4:
            baseline_triggered = True

        known_destinations = record.get("known_destinations", document.get("known_destinations", []) if isinstance(document, dict) else [])
        destination = str(record.get("dst_host", record.get("destination", record.get("dst_ip", "")))).strip().lower()
        if isinstance(known_destinations, list) and known_destinations and destination:
            known = {str(item).strip().lower() for item in known_destinations}
            if destination not in known and bytes_out >= 1_000_000:
                rare_destination_triggered = True

        if _is_off_hours(record) and bytes_out >= 1_000_000:
            off_hours_triggered = True

        if bytes_out >= 1_000_000 and any(host in destination for host in _PERSONAL_CLOUD_HOSTS):
            personal_cloud_triggered = True

    if baseline_triggered:
        evidence.append(("User Egress Baseline Deviation", "Outbound volume is at least four times the supplied per-user baseline.", 25))
        score += 25
    if rare_destination_triggered:
        evidence.append(("Rare Egress Destination", "A high-volume transfer targets a destination absent from the supplied user baseline.", 20))
        score += 20
    if off_hours_triggered:
        evidence.append(("Off-Hours Egress", "A high-volume outbound transfer occurred during the declared or UTC off-hours window.", 15))
        score += 15
    if personal_cloud_triggered:
        evidence.append(("Personal Cloud Upload", "A high-volume transfer targets a recognized personal cloud-storage host.", 20))
        score += 20

    ordered_records = sorted(
        records,
        key=lambda item: str(item.get("timestamp", "")),
    )
    archive_seen = False
    for record in ordered_records:
        activity = " ".join(
            str(record.get(key, ""))
            for key in ("event_type", "action", "operation", "command")
        ).lower()
        if any(term in activity for term in _ARCHIVE_TERMS):
            archive_seen = True
        elif archive_seen and any(term in activity for term in _UPLOAD_TERMS):
            evidence.append(("Archive-Then-Upload Sequence", "Telemetry shows archive or compression activity followed by an upload.", 25))
            score += 25
            break

    return {
        "risk_score": min(99, score),
        "indicators": [
            {"name": name, "weight": weight}
            for name, _, weight in evidence
        ],
        "reasons": list(dict.fromkeys(reason for _, reason, _ in evidence)),
        "sensitive_data_detected": any(
            name in {"Payment Card Data", "Aadhaar-like Identifier", "PAN-like Identifier", "Credential or Private-Key Material"}
            for name, _, _ in evidence
        ),
    }
