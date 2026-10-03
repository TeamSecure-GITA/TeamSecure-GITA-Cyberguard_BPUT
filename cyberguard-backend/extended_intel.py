from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse

from threat_intel import extract_iocs


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
    text = payload.strip()
    lowered = text.lower()
    score = 8
    reasons: list[str] = []

    urgency_terms = ["urgent", "verify", "immediate", "account suspended", "password reset", "security alert", "final warning", "action required"]
    if any(term in lowered for term in urgency_terms):
        score += 25
        reasons.append("Urgency and credential pressure language detected.")

    authority_terms = ["admin", "registrar", "director", "official", "finance", "security team", "support desk"]
    if any(term in lowered for term in authority_terms):
        score += 18
        reasons.append("Authority impersonation language detected.")

    request_terms = ["transfer", "otp", "verify credentials", "click here", "confirm identity", "update payment", "gift card", "wire", "reset password"]
    if any(term in lowered for term in request_terms):
        score += 20
        reasons.append("Request coercion suggests credential theft or financial abuse.")

    urls = re.findall(r"https?://[^\s<>'\"]+", text)
    emails = re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text)
    values = list(dict.fromkeys(urls + emails))
    results = [inspect_indicator(value) for value in values]

    for item in results:
        if item["reputation"] == "malicious":
            score = max(score, min(99, item["risk_score"] + 10))
        elif item["reputation"] == "suspicious":
            score = max(score, min(99, item["risk_score"] + 5))

    for url in urls:
        host = urlparse(url).hostname or ""
        if any(token in host for token in ("login", "verify", "secure", "update", "micros0ft", "paypa1")):
            score += 14
            reasons.append(f"Look-alike URL structure was detected for {host}.")
        if any(tld in host for tld in ("xyz", "top", "online", "click", "live", "site")):
            score += 10
            reasons.append("High-risk URL suffix pattern detected.")

    if not values and not reasons:
        score = 8

    score = min(score, 99)
    return {
        "safe": score < 45,
        "risk_score": score,
        "results": results,
        "genome": hashlib.sha256(text.encode("utf-8")).hexdigest()[:16].upper(),
    }


def build_global_threat_map(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[tuple[str, str, float, float], int] = {}
    for incident in incidents:
        metadata = incident.get("metadata") or {}
        location = metadata.get("source_location") if isinstance(metadata, dict) else None
        if not isinstance(location, dict):
            continue
        country = str(location.get("country") or "").strip()
        try:
            latitude = float(location["lat"])
            longitude = float(location["lng"])
        except (KeyError, TypeError, ValueError):
            continue
        if not country or not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
            continue
        category = str(incident.get("category") or "unknown")
        key = (country, category, latitude, longitude)
        grouped[key] = grouped.get(key, 0) + 1

    locations = [
        {
            "country": country,
            "code": country,
            "lat": latitude,
            "lng": longitude,
            "category": category,
            "count": count,
            "source": "reported_metadata",
        }
        for (country, category, latitude, longitude), count in grouped.items()
    ]
    return {
        "locations": sorted(locations, key=lambda item: item["count"], reverse=True),
        "total_events": len(incidents),
        "geolocated_events": sum(grouped.values()),
        "status": "observed" if grouped else "insufficient_data",
    }


def build_identity_heatmap(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    identities: dict[str, dict[str, Any]] = {}
    for incident in incidents:
        risk = max(0, min(99, int(incident.get("risk_score", 0) or 0)))
        for ioc in extract_iocs(str(incident.get("payload", ""))):
            if ioc.get("type") != "email":
                continue
            address = str(ioc.get("value", "")).strip().lower()
            local, separator, domain = address.partition("@")
            if not separator or not local or not domain:
                continue
            identity = identities.setdefault(address, {
                "label": f"{local[0]}***@{domain}",
                "risk_total": 0,
                "incidents": 0,
                "max_risk": 0,
            })
            identity["risk_total"] += risk
            identity["incidents"] += 1
            identity["max_risk"] = max(identity["max_risk"], risk)

    results = [
        {
            "label": identity["label"],
            "risk": round(identity["risk_total"] / identity["incidents"]),
            "incidents": identity["incidents"],
            "max_risk": identity["max_risk"],
        }
        for identity in identities.values()
    ]
    results.sort(key=lambda item: (item["risk"], item["incidents"]), reverse=True)
    return {
        "identities": results,
        "status": "observed" if results else "insufficient_data",
        "basis": "average risk score of incidents containing the observed email address",
    }


def analyze_trust_media(content: bytes, filename: str, content_type: str) -> dict[str, Any]:
    digest = hashlib.sha256(content).hexdigest()
    from media_engine import analyze_media

    result = analyze_media(content, content_type, filename, "deepfake")
    if result["method"] in {"media-fallback", "metadata-fallback"}:
        raise ValueError("; ".join(result.get("reasons", ["Media could not be inspected."])))
    risk_score = max(0, min(99, int(result.get("score", 0))))
    is_audio = content_type.startswith("audio/") or filename.lower().endswith((".wav", ".flac", ".ogg", ".oga", ".aiff", ".aif", ".mp3", ".m4a", ".aac"))
    is_image = content_type.startswith("image/") or filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff"))
    media_type = "audio" if is_audio else "image" if is_image else "video"
    return {
        "filename": filename,
        "media_type": media_type,
        "risk_score": risk_score,
        "trust_score": 100 - risk_score,
        "voice_authenticity": None,
        "face_authenticity": None,
        "lip_sync_match": None,
        "method": result["method"],
        "calibration": "uncalibrated detector score; not a probability or verified authenticity measure",
        "reasons": result.get("reasons", []),
        "indicators": result.get("indicators", []),
        "model": result.get("pretrained_model"),
        "fingerprint": digest[:16].upper(),
    }
