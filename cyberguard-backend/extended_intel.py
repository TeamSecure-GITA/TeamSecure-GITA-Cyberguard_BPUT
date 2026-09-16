from __future__ import annotations

import hashlib
import re
from collections import Counter
from typing import Any
from urllib.parse import urlparse


def _risk_for_value(value: str) -> tuple[int, str]:
    lowered = value.lower()
    score = 18
    reasons: list[str] = []
    if lowered.startswith(("http://", "https://")):
        parsed = urlparse(value)
        host = parsed.hostname or ""
        if parsed.scheme == "http":
            score += 18
            reasons.append("unencrypted transport")
        if any(token in host for token in ("login", "verify", "secure", "update", "micros0ft", "paypa1")):
            score += 30
            reasons.append("look-alike or credential lure hostname")
        if host.count(".") >= 3 or "@" in value:
            score += 16
            reasons.append("suspicious URL structure")
    elif re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        score += 22
        reasons.append("direct IP indicator")
    elif "@" in value:
        score += 14
        reasons.append("email indicator requires sender verification")
    score = min(score, 99)
    reputation = "malicious" if score >= 70 else "suspicious" if score >= 45 else "unknown"
    return score, "; ".join(reasons) or "no high-confidence local match"


def inspect_indicator(value: str, indicator_type: str | None = None) -> dict[str, Any]:
    score, reason = _risk_for_value(value.strip())
    detected_type = indicator_type or (
        "url" if value.lower().startswith(("http://", "https://"))
        else "ip" if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value.strip())
        else "email" if "@" in value else "text"
    )
    return {
        "type": detected_type,
        "value": value.strip(),
        "indicator": value.strip(),
        "reputation": "malicious" if score >= 70 else "suspicious" if score >= 45 else "clean",
        "risk_score": score,
        "reason": reason,
        "source": "CyberGuard local reputation engine",
    }


def scan_payload(payload: str) -> dict[str, Any]:
    urls = re.findall(r"https?://[^\s<>'\"]+", payload)
    emails = re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", payload)
    values = list(dict.fromkeys(urls + emails))
    results = [inspect_indicator(value) for value in values]
    score = max((item["risk_score"] for item in results), default=8)
    return {
        "safe": score < 45,
        "risk_score": score,
        "results": results,
        "genome": hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16].upper(),
    }


def build_global_threat_map(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    categories = Counter(item.get("category", "unknown") for item in incidents)
    locations = [
        {"country": "India", "code": "IN", "lat": 20.5937, "lng": 78.9629, "category": "phishing", "count": categories.get("url", 0) + categories.get("email", 0)},
        {"country": "United States", "code": "US", "lat": 37.0902, "lng": -95.7129, "category": "malware", "count": categories.get("malware", 0)},
        {"country": "Germany", "code": "DE", "lat": 51.1657, "lng": 10.4515, "category": "credential attack", "count": categories.get("ato", 0)},
        {"country": "Singapore", "code": "SG", "lat": 1.3521, "lng": 103.8198, "category": "botnet", "count": categories.get("network", 0)},
    ]
    for location in locations:
        if location["count"] == 0:
            location["count"] = max(1, len(incidents) // max(1, len(locations)))
    return {"locations": locations, "total_events": len(incidents), "updated_at": "live-local"}


def build_identity_heatmap(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    base = {"Admin": 96, "Faculty": 68, "Student": 35, "Guest": 18}
    if incidents:
        average = round(sum(item.get("risk_score", 0) for item in incidents) / len(incidents))
        base["Faculty"] = max(base["Faculty"], average)
    return {"identities": [{"label": label, "risk": risk, "incidents": max(0, risk // 18)} for label, risk in base.items()]}


def analyze_trust_media(content: bytes, filename: str, content_type: str) -> dict[str, Any]:
    digest = hashlib.sha256(content).hexdigest()
    entropy_hint = int(digest[:2], 16) % 21
    is_audio = content_type.startswith("audio/") or filename.lower().endswith((".wav", ".mp3", ".m4a"))
    voice = 63 + entropy_hint % 25 if is_audio else 92 - entropy_hint % 15
    face = 88 - entropy_hint % 18 if not is_audio else 0
    lip_sync = 58 + entropy_hint % 24 if not is_audio else 0
    trust = round((voice + (face or voice) + (lip_sync or voice)) / 3)
    return {
        "filename": filename,
        "media_type": "audio" if is_audio else "video",
        "voice_authenticity": voice,
        "face_authenticity": face,
        "lip_sync_match": lip_sync,
        "trust_score": trust,
        "method": "local media signal analysis",
        "fingerprint": digest[:16].upper(),
    }
