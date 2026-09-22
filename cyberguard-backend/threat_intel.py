import hashlib
import ipaddress
import os
import re
from typing import Any
from urllib.parse import urlparse

import requests

URL_PATTERN = re.compile(r"https?://[^\s'\"]+")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
KNOWN_BAD_DOMAINS = {"bput-results-2026.xyz", "secure-login.xyz", "bput-ac-in.xyz"}
KNOWN_BAD_IPS = {"192.168.1.105"}


def extract_iocs(payload: str) -> list[dict[str, str]]:
    iocs = []
    seen = set()
    for match in URL_PATTERN.findall(payload):
        value = match.rstrip(".,);]")
        if value not in seen:
            parsed = urlparse(value)
            iocs.append({"type": "url", "value": value, "indicator": parsed.hostname or value, "reputation": "suspicious" if parsed.scheme != "https" else "unknown"})
            seen.add(value)
    for value in IP_PATTERN.findall(payload):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        if value not in seen:
            iocs.append({"type": "ip", "value": value, "indicator": value, "reputation": "private" if ipaddress.ip_address(value).is_private else "unknown"})
            seen.add(value)
    for value in EMAIL_PATTERN.findall(payload):
        if value not in seen:
            iocs.append({"type": "email", "value": value, "indicator": value, "reputation": "unknown"})
            seen.add(value)
    for value in HASH_PATTERN.findall(payload):
        if value not in seen:
            iocs.append({"type": "hash", "value": value, "indicator": value, "reputation": "unknown", "sha256": hashlib.sha256(value.encode()).hexdigest()})
            seen.add(value)
    return iocs


def _local_reputation(indicator: dict[str, str]) -> dict[str, Any]:
    value = indicator["indicator"].lower()
    if indicator["type"] == "url":
        host = (urlparse(indicator["value"]).hostname or value).lower()
        if host in KNOWN_BAD_DOMAINS:
            return {"reputation": "malicious", "risk_score": 96, "source": "local-blocklist"}
        if host.endswith((".xyz", ".top", ".click", ".zip")):
            return {"reputation": "suspicious", "risk_score": 76, "source": "local-heuristic"}
    if indicator["type"] == "ip":
        if value in KNOWN_BAD_IPS:
            return {"reputation": "malicious", "risk_score": 94, "source": "local-blocklist"}
        if ipaddress.ip_address(value).is_private:
            return {"reputation": "private", "risk_score": 12, "source": "local-heuristic"}
    if indicator["type"] == "hash":
        return {"reputation": "unknown", "risk_score": 35, "source": "local-heuristic"}
    return {"reputation": indicator.get("reputation", "unknown"), "risk_score": 20, "source": "local-heuristic"}


def _live_reputation(indicator: dict[str, str]) -> dict[str, Any] | None:
    value = indicator["indicator"]
    if indicator["type"] == "url" and os.getenv("CYBERGUARD_URLHAUS_AUTH_KEY"):
        try:
            response = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": indicator["value"]}, headers={"Auth-Key": os.getenv("CYBERGUARD_URLHAUS_AUTH_KEY")}, timeout=5)
            response.raise_for_status()
            payload = response.json()
            if payload.get("query_status") == "ok":
                return {"reputation": "malicious", "risk_score": 98, "source": "URLhaus"}
            return {"reputation": "unknown", "risk_score": 20, "source": "URLhaus"}
        except (requests.RequestException, ValueError):
            return {"enrichment_error": "URLhaus-unavailable"}
    if indicator["type"] == "ip" and os.getenv("CYBERGUARD_ABUSEIPDB_KEY"):
        try:
            response = requests.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": value, "maxAgeInDays": 90}, headers={"Key": os.getenv("CYBERGUARD_ABUSEIPDB_KEY"), "Accept": "application/json"}, timeout=5)
            response.raise_for_status()
            score = int(response.json().get("data", {}).get("abuseConfidenceScore", 0))
            return {"reputation": "malicious" if score >= 50 else "unknown", "risk_score": score, "source": "AbuseIPDB"}
        except (requests.RequestException, ValueError):
            return {"enrichment_error": "AbuseIPDB-unavailable"}
    return None


def enrich_iocs(iocs: list[dict[str, str]]) -> list[dict[str, Any]]:
    enriched = []
    external_url = os.getenv("CYBERGUARD_THREAT_INTEL_URL")
    for ioc in iocs:
        result = {**ioc, **_local_reputation(ioc)}
        live = _live_reputation(ioc)
        if live:
            result.update(live)
        if external_url:
            try:
                response = requests.post(external_url, json={"indicator": ioc["indicator"], "type": ioc["type"]}, timeout=3)
                response.raise_for_status()
                external = response.json()
                result.update({key: external[key] for key in ("reputation", "risk_score", "source") if key in external})
            except (requests.RequestException, ValueError):
                result["enrichment_error"] = "external-provider-unavailable"
        enriched.append(result)
    return enriched


def ioc_similarity(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> int:
    """Return an explainable 0-100 overlap score for two IOC sets."""
    left_values = {item.get("indicator", item.get("value", "")).lower() for item in left if item.get("indicator", item.get("value"))}
    right_values = {item.get("indicator", item.get("value", "")).lower() for item in right if item.get("indicator", item.get("value"))}
    union = left_values | right_values
    return round(len(left_values & right_values) / len(union) * 100) if union else 0
