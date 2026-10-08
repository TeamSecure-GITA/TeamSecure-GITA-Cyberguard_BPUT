import json
import math
import os
import re
import statistics
from collections.abc import Mapping
from difflib import SequenceMatcher
from datetime import datetime
from pathlib import Path
from typing import List
from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree
from regional_scam_detector import analyze_regional_scam
from dlp_engine import analyze_dlp

import tldextract

try:
    import joblib
except ImportError:
    joblib = None

MODEL_PATH = Path(__file__).parent / "models" / "threat_text_model.joblib"
FALLBACK_MODEL_PATH = Path(__file__).parent / "models" / "threat_text_model_fallback.json"


def load_brand_domains(path: str | Path | None = None) -> dict[str, str]:
    config_path = Path(path or os.getenv("CYBERGUARD_BRAND_DOMAINS_FILE", Path(__file__).parent / "data" / "brand_domains.json"))
    try:
        configured = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    brands = configured.get("brands", configured) if isinstance(configured, dict) else {}
    if not isinstance(brands, dict):
        return {}
    return {
        brand.lower(): domain.lower().rstrip(".")
        for brand, domain in brands.items()
        if isinstance(brand, str)
        and isinstance(domain, str)
        and re.fullmatch(r"[a-z0-9]{2,30}", brand.lower())
        and re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain.lower().rstrip("."))
    }


BRAND_DOMAINS = load_brand_domains()
try:
    TEXT_MODEL_THRESHOLD = max(0.0, min(100.0, float(os.getenv("CYBERGUARD_TEXT_MODEL_THRESHOLD", "50"))))
except ValueError:
    TEXT_MODEL_THRESHOLD = 50.0
TEXT_MODEL = None
FALLBACK_TEXT_MODEL = None
if os.getenv("CYBERGUARD_LOAD_TEXT_MODEL", "true").lower() in {"1", "true", "yes"} and joblib and MODEL_PATH.exists():
    try:
        TEXT_MODEL = joblib.load(MODEL_PATH)
    except Exception:
        TEXT_MODEL = None
if os.getenv("CYBERGUARD_LOAD_TEXT_MODEL", "true").lower() in {"1", "true", "yes"} and FALLBACK_MODEL_PATH.exists():
    try:
        FALLBACK_TEXT_MODEL = json.loads(FALLBACK_MODEL_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        FALLBACK_TEXT_MODEL = None


def model_signal(payload: str) -> tuple[int, dict | None]:
    try:
        from transformer_text import classify
        transformer_result = classify(payload)
    except Exception:
        transformer_result = None
    if transformer_result:
        return transformer_result["score"], {"name": "Fine-tuned Transformer Output", "model_output": transformer_result["score"], "model": transformer_result["model"]}
    if TEXT_MODEL is not None:
        probability = float(TEXT_MODEL.predict_proba([payload])[0][1])
    elif FALLBACK_TEXT_MODEL is not None:
        words = set(re.findall(r"[a-z0-9]{2,}", payload.lower()))
        likelihoods = FALLBACK_TEXT_MODEL["likelihoods"]
        log_scores = {}
        for label in ("0", "1"):
            prior = max(float(FALLBACK_TEXT_MODEL["priors"].get(label, 0.5)), 1e-9)
            score = math.log(prior)
            for word, probability in likelihoods[label].items():
                score += math.log(max(probability if word in words else 1 - probability, 1e-9))
            log_scores[label] = score
        maximum = max(log_scores.values())
        denominator = sum(math.exp(value - maximum) for value in log_scores.values())
        probability = math.exp(log_scores["1"] - maximum) / max(denominator, 1e-9)
    else:
        return 0, None
    score = round(probability * 100)
    indicator = {"name": "Trained Text Model Output", "model_output": score, "model": "TF-IDF + Logistic Regression" if TEXT_MODEL is not None else FALLBACK_TEXT_MODEL["algorithm"]}
    if TEXT_MODEL is not None:
        indicator["feature_attribution"] = model_feature_attribution(payload)
    return score, indicator


def predict_threat_category(payload: str) -> dict:
    """Route unlabelled text to a likely analysis path and expose alternatives.

    This intentionally uses transparent input-shape and keyword evidence until a
    labelled, multi-class training corpus is available; the scores are rankings,
    not calibrated probabilities.
    """
    text = payload.lower()
    scores = {
        "phishing": 10,
        "url": 5,
        "impersonation": 5,
        "ato": 0,
        "network": 0,
        "system_logs": 0,
        "malware": 0,
    }
    if re.search(r"https?://|www\.", text):
        scores["url"] += 40
        scores["phishing"] += 20
    if re.search(r"(?:from|reply-to|return-path):|subject:", text):
        scores["phishing"] += 35
    if re.search(r"\b(?:otp|password|verify|account suspended|payment|urgent|upi|gift card)\b", text):
        scores["phishing"] += 25
    if re.search(r"\b(?:ceo|director|registrar|principal|police|cbi|official|bank)\b", text):
        scores["impersonation"] += 30
    if re.search(r"\b(?:login|failed|token|session|device|mfa|authentication|spray)\b", text):
        scores["ato"] += 35
    if re.search(r"\b(?:src_ip|dst_ip|src_port|dst_port|bytes_in|bytes_out|tcp|udp|flow)\b", text):
        scores["network"] += 55
    if re.search(r"\b(?:eventid|event_id|syslog|powershell|process|service installed|auditd)\b", text):
        scores["system_logs"] += 50
    if re.search(r"\b(?:eicar|ransomware|powershell encoded|macro|malware|sha256)\b", text):
        scores["malware"] += 45

    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    best_category, best_score = ranked[0]
    denominator = sum(max(score, 1) for _, score in ranked[:3])
    candidates = [
        {"category": category, "score": round(max(score, 1) / denominator * 100)}
        for category, score in ranked[:3]
    ]
    return {
        "category": best_category,
        "candidates": candidates,
        "method": "transparent_text_routing_rules",
        "calibration": "Candidate scores are relative rankings, not probabilities.",
        "confidence": "medium" if best_score >= 35 else "low",
    }


def model_feature_attribution(payload: str, limit: int = 5) -> dict:
    """Explain a linear text-model margin without presenting terms as causal evidence."""
    if TEXT_MODEL is None:
        return {"status": "unavailable", "reason": "The deployed text model does not expose linear feature weights.", "features": []}
    try:
        vectorizer = TEXT_MODEL.named_steps["tfidf"]
        classifier = TEXT_MODEL.named_steps["classifier"]
        if len(classifier.coef_) != 1 or len(classifier.classes_) != 2:
            return {"status": "unavailable", "reason": "Feature attribution supports only binary linear classifiers.", "features": []}
        values = vectorizer.transform([payload]).tocsr()
        coefficients = classifier.coef_[0]
        suspicious_index = list(classifier.classes_).index(1)
        direction = 1 if suspicious_index == 1 else -1
        contributions = []
        feature_names = vectorizer.get_feature_names_out()
        for index, value in zip(values.indices, values.data):
            contribution = float(value) * float(coefficients[index]) * direction
            if contribution == 0:
                continue
            term = str(feature_names[index])
            if re.search(r"[@:/\\\d]", term) or len(term) > 48:
                term = "[redacted feature]"
            contributions.append({
                "feature": term,
                "effect": "suspicious" if contribution > 0 else "benign",
                "logit_contribution": round(contribution, 5),
            })
        contributions.sort(key=lambda item: abs(item["logit_contribution"]), reverse=True)
        return {
            "status": "available",
            "method": "tfidf_logistic_logit_contribution",
            "interpretation": "Signed local model-margin contribution; not causal evidence or a calibrated probability.",
            "features": contributions[:max(1, min(int(limit), 10))],
        }
    except (AttributeError, KeyError, TypeError, ValueError, IndexError):
        return {"status": "unavailable", "reason": "The configured model pipeline is incompatible with linear feature attribution.", "features": []}

def analyze_phishing_and_url(payload: str) -> tuple[int, List[str], List[dict]]:
    score = 5
    reasons = []
    indicators = []

    payload_lower = payload.lower()
    urgency_keywords = ["urgent", "verify", "immediate", "account suspended", "account locked", "password reset", "action required", "final warning", "security alert"]
    detected_keywords = [kw for kw in urgency_keywords if kw in payload_lower]
    if detected_keywords:
        score += 6
        reasons.append(f"High-urgency language and social engineering indicators detected ({', '.join(detected_keywords)}).")
        indicators.append({"name": "Language Pressure Index", "weight": 6})

    authority_terms = ["admin", "registrar", "director", "finance", "bank", "support", "official", "security team"]
    matched_authority = [term for term in authority_terms if term in payload_lower]
    credential_requests = ["otp", "password", "verify credentials", "click here", "confirm identity", "reset password", "verification code", "upi pin"]
    matched_credentials = [term for term in credential_requests if term in payload_lower]
    financial_requests = ["transfer", "send money", "pay now", "wire", "gift card", "payment due"]
    matched_financial = [term for term in financial_requests if term in payload_lower]
    if matched_credentials:
        score += 24
        reasons.append(f"Credential-harvesting language requests sensitive information ({', '.join(matched_credentials)}).")
        indicators.append({"name": "Credential Theft Construct", "weight": 24})
    if matched_financial:
        score += 8
        reasons.append(f"Financial-action language is present ({', '.join(matched_financial)}); verify the request independently.")
        indicators.append({"name": "Financial Request Signal", "weight": 8})

    sender_domains = re.findall(r"from:.*?@([\w.-]+\.[A-Za-z]{2,})", payload_lower)
    sender_mismatch = bool(sender_domains and any(domain.endswith(("gmail.com", "outlook.com", "yahoo.com", "hotmail.com")) for domain in sender_domains))
    if sender_mismatch:
        score += 10
        reasons.append("The sender channel does not match the claimed institutional identity.")
        indicators.append({"name": "Sender Identity Mismatch", "weight": 10})

    if matched_authority and (matched_credentials or sender_mismatch or re.search(r"https?://", payload_lower)):
        score += 12
        reasons.append(f"A request invokes an institutional identity ({', '.join(matched_authority)}) in a suspicious context.")
        indicators.append({"name": "Authority Impersonation Signal", "weight": 12})

    if re.search(r"https?://", payload_lower):
        url_score, url_reasons, url_indicators = analyze_url_intelligence(payload)
        url_contribution = min(max(url_score - 10, 0), 55)
        score += url_contribution
        reasons.extend(url_reasons)
        indicators.extend(url_indicators)

    if not reasons:
        reasons.append("No phishing or social-engineering patterns matched the content baseline.")
        indicators.append({"name": "Baseline Email Hygiene", "weight": 1})

    return min(score, 99), reasons, indicators


def analyze_url_intelligence(payload: str) -> tuple[int, List[str], List[dict]]:
    score = 10
    reasons = []
    indicators = []
    urls = re.findall(r"https?://[^\s<>\"']+", payload.lower())
    risky_tlds = {"xyz", "top", "online", "live", "site", "click", "zip"}
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"}
    trusted_domains = set(BRAND_DOMAINS.values())
    for raw_url in urls:
        url = raw_url.rstrip(".,;:!?)]}")
        parsed_url = urlparse(url)
        extracted = tldextract.extract(url)
        host = extracted.fqdn or extracted.domain
        registered_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        lexical_entropy = 0.0
        if host:
            frequencies = [host.count(character) / len(host) for character in set(host)]
            lexical_entropy = -sum(frequency * math.log2(frequency) for frequency in frequencies)
        digit_ratio = sum(character.isdigit() for character in host) / max(len(host), 1)
        if len(host) >= 28 or digit_ratio > 0.25 or host.count("-") >= 2:
            score += 15
            reasons.append(f"URL lexical profile is unusual (length {len(host)}, digit ratio {digit_ratio:.2f}).")
            indicators.append({"name": "Lexical URL Anomaly", "weight": 15, "entropy": round(lexical_entropy, 3)})
        if extracted.suffix in risky_tlds:
            score += 25
            reasons.append(f"URL intelligence flagged a high-risk top-level domain ({extracted.suffix}).")
            indicators.append({"name": "URL Reputation Risk", "weight": 25})
        if host in shorteners or extracted.domain in shorteners:
            score += 28
            reasons.append("Redirect shortener obscures the destination and requires analyst expansion.")
            indicators.append({"name": "Redirect Obfuscation", "weight": 28})
        if "xn--" in host or re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", parsed_url.hostname or ""):
            score += 30
            reasons.append("URL uses an IDN or raw IP host, reducing domain identity confidence.")
            indicators.append({"name": "Raw IP or IDN Host", "weight": 30})
        for brand, trusted_domain in BRAND_DOMAINS.items():
            similarity = SequenceMatcher(None, registered_domain, trusted_domain).ratio()
            if brand in extracted.domain and registered_domain not in trusted_domains:
                score += 30
                reasons.append(f"Brand-like domain requires look-alike and typosquatting review ({host}).")
                indicators.append({"name": "Typosquatting Similarity", "weight": 30, "similarity": round(similarity, 3)})
                break
        query_keys = set(parse_qs(parsed_url.query).keys())
        if query_keys.intersection({"url", "u", "redirect", "redirect_uri", "next", "return", "continue"}):
            score += 20
            reasons.append("Redirect parameter can conceal a second destination and needs expansion.")
            indicators.append({"name": "Suspicious Redirect Chain", "weight": 20})
    if len(urls) > 1:
        score += 15
        reasons.append(f"Multiple URL hops detected ({len(urls)} destinations in one artifact).")
        indicators.append({"name": "Redirect Hop Count", "weight": 15, "observed_hops": len(urls)})
    if not urls:
        reasons.append("No URL artifact was supplied for reputation enrichment.")
        indicators.append({"name": "URL Extraction", "weight": 1, "observed_urls": 0})
    return min(score, 99), reasons, indicators


def analyze_screenshot_brand_mismatches(text: str) -> list[dict[str, str]]:
    url_pattern = r"(?:(?:https?://|www\.)[^\s<>\"'`]+|(?:[a-z0-9](?:[a-z0-9-]{0,62}\.)+[a-z]{2,63})(?:/[^\s<>\"'`]*)?)"
    urls = re.findall(url_pattern, text, re.IGNORECASE)
    visible_text = re.sub(url_pattern, " ", text, flags=re.IGNORECASE)
    if not re.search(r"\b(?:sign[\s-]?in|log[\s-]?in|password|passcode|user\s*name|email address|verify your account|account verification)\b", visible_text, re.IGNORECASE):
        return []

    domains = set()
    for raw_url in urls:
        candidate = raw_url.rstrip(".,;:!?)]}")
        parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if hostname:
            extracted = tldextract.extract(hostname)
            domains.add((hostname, f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else hostname))

    mismatches = []
    for brand, trusted_domain in BRAND_DOMAINS.items():
        if not re.search(rf"\b{re.escape(brand)}\b", visible_text, re.IGNORECASE):
            continue
        for hostname, registered_domain in domains:
            if registered_domain != trusted_domain and not registered_domain.endswith(f".{trusted_domain}"):
                mismatches.append({
                    "brand": brand,
                    "observed_domain": hostname,
                    "expected_domain": trusted_domain,
                })

    return mismatches


def analyze_account_takeover(payload: str) -> tuple[int, List[str], List[dict]]:
    score = 20
    reasons = []
    indicators = []
    
    if "failed" in payload.lower() or "unauthorized" in payload.lower():
        score += 65
        reasons.append("High-frequency failed authentication attempts from anomalous IP subnets (Password Spraying signature).")
        indicators.append({"name": "Authentication Anomaly Index", "weight": 35})
        indicators.append({"name": "Geographic / IP Distance Velocity", "weight": 30})
        
    return min(score, 99), reasons, indicators


def analyze_behavioral_ato(payload: str) -> tuple[int, List[str], List[dict]]:
    payload_lower = payload.lower()
    score = 5
    reasons = []
    indicators = []
    signals = {
        "failed authentication": (25, "Repeated failed authentication events indicate credential attack behavior."),
        "password spray": (35, "Password-spraying behavior targets multiple accounts with shared credentials."),
        "impossible travel": (30, "Impossible-travel activity indicates a geographic velocity anomaly."),
        "new device": (18, "A new device or session appeared outside the account baseline."),
        "mfa fatigue": (30, "Repeated MFA prompts indicate possible push-bombing behavior."),
        "session hijack": (35, "Session-hijacking language indicates active account compromise risk."),
        "unauthorized": (22, "Unauthorized access evidence increases account takeover likelihood."),
    }
    for signal, (increment, reason) in signals.items():
        if signal in payload_lower:
            score += increment
            reasons.append(reason)
            indicators.append({"name": f"{signal.title()} Signal", "weight": increment})
    try:
        event = json.loads(payload)
        if isinstance(event, dict):
            failed_count = int(event.get("failed_attempts", 0))
            total_attempts = max(int(event.get("total_attempts", failed_count)), 1)
            failure_rate = failed_count / total_attempts
            distinct_accounts = int(event.get("distinct_accounts", 1))
            distinct_countries = int(event.get("distinct_countries", 1))
            anomaly_score = 0
            if failure_rate >= 0.5:
                anomaly_score += 25
                reasons.append(f"Structured telemetry shows a high failure rate ({failure_rate:.0%}).")
            if failed_count >= 5:
                anomaly_score += 20
                reasons.append(f"Behavioral baseline exceeded with {failed_count} failed attempts.")
            if distinct_accounts >= 5:
                anomaly_score += 20
                reasons.append(f"Password-spray breadth reached {distinct_accounts} accounts.")
            if distinct_countries >= 2 or event.get("impossible_travel"):
                anomaly_score += 25
                reasons.append("Structured telemetry indicates geographic velocity or impossible travel.")
            if event.get("new_device") or int(event.get("mfa_denials", 0)) >= 3:
                anomaly_score += 15
                reasons.append("New-device or repeated MFA-denial activity deviates from the account baseline.")
            if anomaly_score:
                score += anomaly_score
                indicators.append({"name": "Structured Behavioural Anomaly", "weight": anomaly_score})
            indicators.append({"name": "Failure Rate", "observed_value": round(failure_rate, 3)})
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    if not reasons:
        reasons.append("No account-behavior deviation matched the ATO baseline.")
        indicators.append({"name": "Behavioral Baseline Match", "weight": 1})
    return min(score, 99), reasons, indicators


def analyze_impersonation(payload: str) -> tuple[int, List[str], List[dict]]:
    payload_lower = payload.lower()
    score = 5
    reasons = []
    indicators = []
    authority_terms = ["registrar", "principal", "administrator", "support desk", "finance", "police", "government", "director"]
    request_terms = ["transfer", "gift card", "otp", "password", "verification code", "bank details", "wire"]
    urgency_terms = ["urgent", "immediately", "asap", "today", "final warning"]
    matched_authority = [term for term in authority_terms if term in payload_lower]
    matched_requests = [term for term in request_terms if term in payload_lower]
    matched_urgency = [term for term in urgency_terms if term in payload_lower]
    claimed_identity = re.search(r"(?:from|as|i am|this is)\s+([a-z][a-z -]{2,40})", payload_lower)
    if matched_authority:
        score += 30
        reasons.append(f"Authority-role language suggests a trusted-identity impersonation attempt ({', '.join(matched_authority)}).")
        indicators.append({"name": "Trusted Role Impersonation", "weight": 30})
    if matched_requests:
        score += 25
        reasons.append(f"High-impact request pattern detected ({', '.join(matched_requests)}).")
        indicators.append({"name": "Request Coercion Pattern", "weight": 25})
    if matched_urgency:
        score += 15
        reasons.append(f"Urgency and authority pressure detected ({', '.join(matched_urgency)}).")
        indicators.append({"name": "Urgency Pressure", "weight": 15})
    if claimed_identity:
        score += 10
        reasons.append(f"Claimed identity extracted from communication ({claimed_identity.group(1).strip()}).")
        indicators.append({"name": "Claimed Identity", "weight": 10})
    if re.search(r"from:.*@(gmail|outlook|yahoo)\.", payload_lower) or (matched_authority and re.search(r"@(gmail|outlook|yahoo)\.", payload_lower)):
        score += 20
        reasons.append("Contact channel does not match the claimed institutional identity.")
        indicators.append({"name": "Contact Mismatch", "weight": 20})
    if not reasons:
        reasons.append("No trusted-identity impersonation pattern matched.")
        indicators.append({"name": "Identity Consistency", "weight": 1})
    return min(score, 99), reasons, indicators


def analyze_deepfake(payload: str) -> tuple[int, List[str], List[dict]]:
    payload_lower = payload.lower()
    score = 35
    reasons = ["Synthetic-media triage enabled; media decoder evidence is combined with content signals."]
    indicators = [{"name": "Synthetic Media Triage", "weight": 1}]
    signals = {"voice clone": 20, "face swap": 25, "lip sync": 18, "generated": 15, "synthetic": 15, "deepfake": 25}
    for signal, increment in signals.items():
        if signal in payload_lower:
            score += increment
            reasons.append(f"Synthetic-media marker detected: {signal}.")
            indicators.append({"name": f"{signal.title()} Evidence", "weight": increment})
    return min(score, 99), reasons, indicators


def _case_value(record: Mapping[str, object], *keys: str) -> object:
    lowered = {str(key).lower(): value for key, value in record.items()}
    return next((lowered[key.lower()] for key in keys if key.lower() in lowered), None)


def _unwrap_event_value(value: object) -> object:
    if isinstance(value, Mapping):
        return _case_value(value, "#text", "value", "@systemtime", "systemtime")
    return value


def _normalise_system_log_record(record: Mapping[str, object]) -> dict[str, object]:
    event_document = _case_value(record, "Event", "event")
    event_document = event_document if isinstance(event_document, Mapping) else record
    system = _case_value(event_document, "System", "system")
    system = system if isinstance(system, Mapping) else {}
    event_data = _case_value(event_document, "EventData", "event_data", "eventData")
    event_data = event_data if isinstance(event_data, Mapping) else {}
    data_fields = _case_value(event_data, "Data", "data")
    fields = {}
    if isinstance(data_fields, list):
        for item in data_fields:
            if not isinstance(item, Mapping):
                continue
            field_name = _case_value(item, "@Name", "Name", "name")
            field_value = _unwrap_event_value(item)
            if field_name and field_value is not None:
                fields[str(field_name).lower().replace(" ", "_")] = field_value
    elif isinstance(data_fields, Mapping):
        fields.update({str(key).lower().replace(" ", "_"): _unwrap_event_value(value) for key, value in data_fields.items()})
    for key in ("image_path", "service_path", "command", "task_command", "targetusername", "subjectusername"):
        value = _case_value(event_data, key)
        if value is not None:
            fields[key] = _unwrap_event_value(value)

    event_id = _unwrap_event_value(_case_value(system, "EventID", "event_id") or _case_value(record, "event_id", "eventId", "EventID", "id"))
    event_data_values = fields
    raw_message = _case_value(record, "message", "Message", "description")
    if raw_message is None:
        raw_message = _case_value(_case_value(event_document, "RenderingInfo", "rendering_info") or {}, "Message", "message")
    explicit_type = _case_value(record, "event_type", "eventType", "action")
    if isinstance(explicit_type, Mapping):
        explicit_type = _unwrap_event_value(explicit_type)
    timestamp = _unwrap_event_value(_case_value(system, "TimeCreated", "time_created") or _case_value(record, "timestamp", "time", "@timestamp"))
    computer = _case_value(system, "Computer", "computer") or _case_value(record, "host", "hostname", "computer")
    normalized = {str(key).lower(): _unwrap_event_value(value) for key, value in record.items()}
    normalized.update({"event_id": str(event_id) if event_id is not None else "", "event_type": str(explicit_type or ""), "message": str(raw_message or ""), "timestamp": str(timestamp or ""), "host": str(computer or "")})
    normalized.update(event_data_values)
    if "imagepath" in normalized and "image_path" not in normalized:
        normalized["image_path"] = normalized["imagepath"]
    if "commandline" in normalized and "command" not in normalized:
        normalized["command"] = normalized["commandline"]
    if "newprocessname" in normalized and "image_path" not in normalized:
        normalized["image_path"] = normalized["newprocessname"]
    inferred_types = {"1102": "audit_log_cleared", "4625": "failed_login", "4672": "privilege_change", "4720": "account_created", "4728": "admin_grant", "4732": "admin_grant", "4756": "admin_grant", "4698": "scheduled_task_created", "7045": "service_installed"}
    if not normalized["event_type"]:
        normalized["event_type"] = inferred_types.get(normalized["event_id"], "")
    return normalized


def _parse_system_log_lines(payload: str) -> list[dict[str, object]]:
    records = []
    for line in payload.splitlines():
        line = line.strip()
        if not line:
            continue
        record: dict[str, object] = {"message": line}
        priority = re.match(r"^<(\d{1,3})>", line)
        if priority:
            syslog_priority = int(priority.group(1))
            severity = syslog_priority % 8
            record["severity"] = ("emergency", "alert", "critical", "error", "warning", "notice", "info", "debug")[severity]
            record["facility"] = syslog_priority // 8
        message = line.rsplit(": ", 1)[-1].lower()
        if any(signal in message for signal in ("failed password", "authentication failure", "invalid user", "failed login")):
            record["event_id"] = "4625"
            record["event_type"] = "failed_login"
        elif "audit" in message and any(signal in message for signal in ("cleared", "deleted", "removed")):
            record["event_id"] = "1102"
            record["event_type"] = "audit_log_cleared"
        elif re.search(r"\b(?:useradd|new user|user created)\b", message):
            record["event_type"] = "account_created"
        elif re.search(r"\b(?:usermod|added to (?:the )?sudo|added to (?:the )?wheel)\b", message):
            record["event_type"] = "privilege_change"
        elif any(marker in message for marker in ("-encodedcommand", " frombase64string", "downloadstring")) or re.search(r"\b(?:curl|wget)\b.{0,200}\|\s*(?:sh|bash)\b", message):
            record["event_type"] = "process_start"
            record["command"] = message
        records.append(record)
    return records


def _parse_windows_event_xml(payload: str) -> list[dict[str, object]]:
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError:
        return []
    event_nodes = [node for node in root.iter() if node.tag.rsplit("}", 1)[-1].lower() == "event"]
    records = []
    for event in event_nodes:
        children = list(event)
        system = next((node for node in children if node.tag.rsplit("}", 1)[-1].lower() == "system"), None)
        event_data = next((node for node in children if node.tag.rsplit("}", 1)[-1].lower() in {"eventdata", "userdata"}), None)
        if system is None:
            continue
        system_fields = {node.tag.rsplit("}", 1)[-1].lower(): node for node in system}
        event_id = system_fields.get("eventid")
        time_created = system_fields.get("timecreated")
        computer = system_fields.get("computer")
        record: dict[str, object] = {
            "event_id": event_id.text.strip() if event_id is not None and event_id.text else "",
            "timestamp": time_created.attrib.get("SystemTime", "") if time_created is not None else "",
            "host": computer.text.strip() if computer is not None and computer.text else "",
        }
        if event_data is not None:
            for node in event_data.iter():
                if node.tag.rsplit("}", 1)[-1].lower() != "data" or not node.attrib.get("Name") or node.text is None:
                    continue
                record[node.attrib["Name"].lower().replace(" ", "_")] = node.text.strip()
        records.append(record)
    return records


def _system_log_records(document: object, payload: str) -> list[dict[str, object]]:
    if isinstance(document, list):
        source_records = document
    elif isinstance(document, Mapping):
        source_records = None
        for key in ("events", "records", "Records", "EventRecords"):
            value = _case_value(document, key)
            if isinstance(value, list):
                source_records = value
                break
        if source_records is None:
            source_records = [document]
    else:
        source_records = _parse_windows_event_xml(payload)
        if not source_records:
            json_lines = []
            for line in payload.splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, Mapping):
                    json_lines.append(item)
            source_records = json_lines or _parse_system_log_lines(payload)
    normalized = [_normalise_system_log_record(record) for record in source_records if isinstance(record, Mapping)]
    if not normalized and isinstance(document, str):
        return _parse_system_log_lines(payload)
    return normalized

def analyze_structured_telemetry(payload: str, category: str) -> tuple[int, List[str], List[dict]]:
    try:
        document = json.loads(payload)
    except (TypeError, json.JSONDecodeError):
        if category != "system_logs":
            return 15, [], []
        document = None
    records = document if isinstance(document, list) else document.get("flows", document.get("events", [document])) if isinstance(document, dict) else []
    if isinstance(records, dict):
        records = [records]
    if category == "system_logs":
        records = _system_log_records(document, payload)
    if not isinstance(records, list):
        return 15, [], []
    score = 15
    reasons = []
    indicators = []

    def number(record: dict, *keys: str) -> float:
        for key in keys:
            try:
                value = float(record.get(key, 0) or 0)
                if math.isfinite(value):
                    return max(0.0, value)
            except (TypeError, ValueError):
                continue
        return 0.0

    if category == "network":
        severity_weights = {
            "1": 45,
            "critical": 45,
            "2": 35,
            "high": 35,
            "3": 20,
            "medium": 20,
            "4": 10,
            "low": 10,
        }
        severity_names = {
            "1": "critical",
            "critical": "critical",
            "2": "high",
            "high": "high",
            "3": "medium",
            "medium": "medium",
            "4": "low",
            "low": "low",
        }
        alert_signatures = {}
        for record in records:
            if not isinstance(record, dict) or str(record.get("event_type", "")).lower() != "alert":
                continue
            signature = str(record.get("signature", "")).strip()
            severity = str(record.get("signature_severity", "")).strip().lower()
            weight = severity_weights.get(severity)
            if not signature or weight is None:
                continue
            key = signature.casefold()
            alert = {
                "name": "Suricata IDS Alert",
                "weight": weight,
                "signature": signature[:256],
                "severity": severity_names[severity],
            }
            for field in ("signature_category", "signature_action", "signature_id"):
                value = record.get(field)
                if value:
                    alert[field.removeprefix("signature_")] = str(value)[:160]
            if key not in alert_signatures or alert_signatures[key]["weight"] < weight:
                alert_signatures[key] = alert
        for alert in sorted(alert_signatures.values(), key=lambda item: item["weight"], reverse=True)[:3]:
            score += alert["weight"]
            reasons.append(
                f"Network sensor reported a {alert['severity']} severity IDS alert: {alert['signature']}."
            )
            indicators.append(alert)

        ports = set()
        for record in records:
            if not isinstance(record, dict):
                continue
            port_values = record.get("destination_ports", record.get("dst_ports", []))
            if isinstance(port_values, list):
                ports.update(str(port) for port in port_values if str(port).isdigit() and 0 < int(port) <= 65535)
            port = record.get("destination_port", record.get("dst_port"))
            if port is not None and str(port).isdigit() and 0 < int(port) <= 65535:
                ports.add(str(port))
            declared_count = number(record, "unique_destination_ports", "distinct_destination_ports")
            if declared_count > len(ports):
                ports.update(f"declared-{index}" for index in range(int(declared_count)))
        if len(ports) >= 10:
            score += min(50, 20 + len(ports))
            reasons.append(f"Flow telemetry shows probing across {len(ports)} destination ports, consistent with network reconnaissance.")
            indicators.append({"name": "Flow Port-Scan Breadth", "weight": min(50, 20 + len(ports)), "unique_destination_ports": len(ports)})

        bytes_out = sum(number(record, "bytes_out", "bytes_sent", "bytes_tx") for record in records if isinstance(record, dict))
        bytes_in = sum(number(record, "bytes_in", "bytes_received", "bytes_rx") for record in records if isinstance(record, dict))
        if bytes_out >= 10_000_000 and bytes_out > max(bytes_in, 1) * 10:
            score += 40
            reasons.append(f"Outbound flow volume is {bytes_out / max(bytes_in, 1):.1f}x inbound volume ({int(bytes_out)} bytes out), consistent with possible exfiltration.")
            indicators.append({"name": "Outbound Flow Volume Ratio", "weight": 40})

        timestamps = []
        for record in records:
            if not isinstance(record, dict):
                continue
            record_timestamps = record.get("timestamps")
            if not isinstance(record_timestamps, list):
                record_timestamps = [record.get("timestamp")]
            for timestamp in record_timestamps:
                if not isinstance(timestamp, str):
                    continue
                try:
                    timestamps.append(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp())
                except ValueError:
                    continue
        intervals = [right - left for left, right in zip(sorted(timestamps), sorted(timestamps)[1:])]
        if len(intervals) >= 4 and 30 <= statistics.mean(intervals) <= 3600 and statistics.pstdev(intervals) / statistics.mean(intervals) <= 0.15:
            score += 25
            reasons.append("Network flows recur at a regular interval, consistent with beaconing behavior.")
            indicators.append({"name": "Regular Flow Beaconing", "weight": 25})

    if category == "api_logs":
        requests_per_minute = max((number(record, "requests_per_minute", "request_rate_per_minute") for record in records if isinstance(record, dict)), default=0)
        for record in records:
            if not isinstance(record, dict):
                continue
            count = number(record, "request_count", "requests")
            duration = number(record, "window_seconds", "duration_seconds")
            if duration > 0:
                requests_per_minute = max(requests_per_minute, count * 60 / duration)
        if requests_per_minute >= 300:
            weight = min(50, 25 + round(requests_per_minute / 100))
            score += weight
            reasons.append(f"API telemetry records {requests_per_minute:.0f} requests per minute, above the configured abuse threshold.")
            indicators.append({"name": "API Request Rate", "weight": weight, "observed_requests_per_minute": round(requests_per_minute)})
        responses = [int(number(record, "status_code", "http_status")) for record in records if isinstance(record, dict) and number(record, "status_code", "http_status")]
        if responses and responses.count(429) / len(responses) >= 0.25:
            score += 20
            reasons.append("A high share of API responses are HTTP 429 rate-limit responses.")
            indicators.append({"name": "API Rate-Limit Responses", "weight": 20})

    if category == "system_logs":
        for record in records:
            if not isinstance(record, dict):
                continue
            event_id = str(record.get("event_id", record.get("eventId", record.get("id", "")))).strip().lower()
            event_type = str(record.get("event_type", record.get("action", record.get("type", "")))).strip().lower()
            count = max(1, int(number(record, "count", "event_count", "occurrences")))
            if event_id == "1102" or "audit_log_cleared" in event_type or "logs_cleared" in event_type:
                score += 45
                reasons.append("System telemetry reports audit-log clearing, which can indicate evidence tampering.")
                indicators.append({"name": "Audit Log Cleared", "weight": 45})
            if event_id in {"4672", "4720", "4728", "4732", "4756"} or any(signal in event_type for signal in ("privilege_change", "admin_grant", "account_created")):
                score += 25
                reasons.append(f"System telemetry reports a privileged identity change (event {event_id or event_type}).")
                indicators.append({"name": "Privileged Identity Change", "weight": 25})
            if event_id == "7045" or "service_installed" in event_type:
                score += 20
                reasons.append("System telemetry reports a newly installed service; verify its publisher and executable path.")
                indicators.append({"name": "New Service Installation", "weight": 20})
                executable = str(record.get("image_path", record.get("service_path", ""))).lower()
                if any(marker in executable for marker in ("\\temp\\", "\\appdata\\", "powershell", "rundll32")):
                    score += 20
                    reasons.append("The new service uses a suspicious executable path or interpreter.")
                    indicators.append({"name": "Suspicious Service Executable", "weight": 20})
            if event_id == "4698" or "scheduled_task_created" in event_type:
                score += 20
                reasons.append("System telemetry reports a new scheduled task; verify its owner and command.")
                indicators.append({"name": "Scheduled Task Creation", "weight": 20})
                task_command = str(record.get("command", record.get("task_command", ""))).lower()
                if "-encodedcommand" in task_command or " -enc " in task_command:
                    score += 20
                    reasons.append("The scheduled task command uses encoded PowerShell arguments.")
                    indicators.append({"name": "Encoded Scheduled Task Command", "weight": 20})
            if event_id == "4688" or "process_start" in event_type or "process_created" in event_type:
                executable = str(record.get("image_path", record.get("newprocessname", ""))).lower()
                command = str(record.get("command", record.get("commandline", ""))).lower()
                message = str(record.get("message", "")).lower()
                suspicious_command = any(marker in command for marker in ("-encodedcommand", " -enc ", "downloadstring", "frombase64string", "invoke-expression"))
                suspicious_location = any(marker in executable for marker in ("\\temp\\", "\\appdata\\", "/tmp/", "/dev/shm/"))
                shell_pipe = bool(re.search(r"\b(?:curl|wget)\b.{0,200}\|\s*(?:sh|bash)\b", message))
                if suspicious_command or suspicious_location or shell_pipe:
                    score += 30
                    reasons.append("Process telemetry combines a suspicious executable location or download/encoded-command pattern.")
                    indicators.append({"name": "Suspicious Process Creation", "weight": 30})

        failed_auth_count = sum(
            max(1, int(number(record, "count", "event_count", "occurrences")))
            for record in records
            if isinstance(record, dict)
            and (
                str(record.get("event_id", record.get("eventId", record.get("id", "")))).strip() == "4625"
                or any(signal in str(record.get("event_type", record.get("action", record.get("type", "")))).lower() for signal in ("failed_login", "authentication_failure"))
            )
        )
        if failed_auth_count >= 10:
            score += 30
            reasons.append(f"System logs contain {failed_auth_count} failed authentication events in the submitted window.")
            indicators.append({"name": "System Authentication Failure Burst", "weight": 30})

        event_rate = max((number(record, "events_per_minute", "event_rate_per_minute") for record in records if isinstance(record, dict)), default=0)
        for record in records:
            if not isinstance(record, dict):
                continue
            duration = number(record, "window_seconds", "duration_seconds")
            count = number(record, "event_count", "events")
            if duration > 0:
                event_rate = max(event_rate, count * 60 / duration)
        if event_rate >= 5000:
            score += 25
            reasons.append(f"System telemetry volume reached {event_rate:.0f} events per minute, indicating a logging burst or flood.")
            indicators.append({"name": "System Log Event-Rate Burst", "weight": 25, "observed_events_per_minute": round(event_rate)})

    return min(score, 99), reasons, indicators


def analyze_technical_activity(payload: str, category: str = "network") -> tuple[int, List[str], List[dict]]:
    payload_lower = payload.lower()
    score = 15
    reasons = []
    indicators = []
    structured_network_payload = False
    if category == "network":
        try:
            structured_network_payload = isinstance(json.loads(payload), (dict, list))
        except (TypeError, json.JSONDecodeError):
            pass
    signatures = {
        "malware": (45, "Malware or executable payload indicators detected."),
        "powershell": (35, "Suspicious PowerShell execution pattern detected."),
        "exfil": (45, "Potential data-exfiltration behavior detected."),
        "large transfer": (40, "Abnormally large data transfer indicator detected."),
        "rate limit": (35, "Possible API abuse or rate-limit evasion detected."),
        "sqlmap": (50, "Automated web/API attack tooling signature detected."),
        "port scan": (40, "Network reconnaissance and port scanning behavior detected."),
        "failed": (30, "Repeated authentication failures detected in telemetry."),
        "unauthorized": (35, "Unauthorized activity indicator detected in logs."),
    }
    if category == "system_logs":
        signatures.pop("powershell")
    if not structured_network_payload:
        for signature, (increment, reason) in signatures.items():
            if signature in payload_lower:
                score += increment
                reasons.append(reason)
                indicators.append({"name": f"{signature.title()} Signature", "weight": increment})
    structured_score, structured_reasons, structured_indicators = analyze_structured_telemetry(payload, category)
    if structured_reasons:
        score = min(99, score + structured_score - 15)
        reasons.extend(structured_reasons)
        indicators.extend(structured_indicators)
    if category == "exfiltration":
        dlp_result = analyze_dlp(payload)
        score = min(99, score + dlp_result["risk_score"])
        reasons.extend(dlp_result["reasons"])
        indicators.extend(dlp_result["indicators"])
    return min(score, 99), reasons, indicators

def adversarial_self_test(category: str, payload: str) -> dict:
    baseline = evaluate_threat_payload(category, payload)
    baseline_score = int(baseline["risk_score"])

    synonym_variant = payload
    for original, replacement in (("urgent", "immediately"), ("verify", "confirm"), ("password", "credentials")):
        synonym_variant = re.sub(rf"\b{original}\b", replacement, synonym_variant, flags=re.IGNORECASE)
    candidates = [
        synonym_variant,
        payload + " Please act now before access is suspended.",
        payload + " secure-login-check.example/confirm",
    ]

    results = []
    unique_variants = []
    seen_variants = {payload}
    for variant in candidates:
        if variant and variant not in seen_variants:
            seen_variants.add(variant)
            unique_variants.append(variant)

    for index, variant in enumerate(unique_variants, start=1):
        variant_result = evaluate_threat_payload(category, variant)
        decay = max(0, baseline_score - int(variant_result["risk_score"]))
        results.append({
            "probe_id": f"probe-{index}",
            "variant": variant[:180],
            "risk_score": int(variant_result["risk_score"]),
            "risk_level": variant_result["risk_level"],
            "confidence_decay": decay,
            "signal_count": int(variant_result.get("signal_count", 0)),
        })

    strongest_decay = max((item["confidence_decay"] for item in results), default=0)
    weak_points = [
        item["probe_id"] for item in results if item["confidence_decay"] >= max(5, strongest_decay * 0.6)
    ]

    return {
        "baseline_score": baseline_score,
        "baseline_level": baseline["risk_level"],
        "confidence_decay": strongest_decay,
        "weak_points": weak_points,
        "adversarial_probes": results,
        "status": "exposed" if strongest_decay >= 10 else "stable",
        "recommendation": "Increase model safeguards around urgency, authority, and redirect behavior." if strongest_decay >= 10 else "Model holds steady under adversarial probes.",
    }


def analyze_login_anomaly(payload: str) -> tuple[int, list[str], list[dict]]:
    """Score structured login telemetry against a deterministic low-risk baseline."""
    try:
        event = json.loads(payload) if isinstance(payload, str) else payload
    except (TypeError, json.JSONDecodeError):
        event = {}
    if not isinstance(event, dict):
        return 0, [], []
    values = [float(event.get(key, 0) or 0) for key in ("failed_attempts", "distinct_accounts", "distinct_countries", "mfa_denials")]
    if not any(values) and not event.get("impossible_travel") and not event.get("new_device"):
        return 0, [], []
    try:
        from sklearn.ensemble import IsolationForest
        import numpy as np
        reference = np.array([[0, 1, 1, 0], [1, 1, 1, 0], [0, 1, 1, 1], [2, 2, 1, 1], [1, 1, 2, 0], [3, 2, 1, 1]])
        model = IsolationForest(n_estimators=48, contamination=0.2, random_state=42).fit(reference)
        anomaly = max(1, min(99, round(50 - float(model.decision_function(np.array([values]))[0]) * 80)))
    except Exception:
        anomaly = min(99, 20 + round(sum(values) * 4))
    reasons = ["Login telemetry deviates from the shared low-risk authentication baseline."]
    indicators = [{"name": "Isolation Forest Login Anomaly", "model_output": anomaly, "weight": 30}]
    if event.get("impossible_travel"):
        reasons.append("Impossible-travel activity is inconsistent with the user baseline.")
        indicators.append({"name": "Impossible Travel", "weight": 25})
    return round(anomaly * 0.7), reasons, indicators


def analyze_authentication_event(payload: str) -> tuple[int, List[str], List[dict]]:
    rule_score, rule_reasons, rule_indicators = analyze_behavioral_ato(payload)
    anomaly_score, anomaly_reasons, anomaly_indicators = analyze_login_anomaly(payload)
    return (
        max(rule_score, anomaly_score),
        list(dict.fromkeys(rule_reasons + anomaly_reasons)),
        rule_indicators + anomaly_indicators,
    )


def evaluate_threat_payload(category: str, payload: str) -> dict:
    if category in {"auth_logs", "anomaly", "ato"}:
        score, reasons, indicators = analyze_authentication_event(payload)
        detection_method = "shared-authentication-risk"
        mitre_techniques = ["T1078", "T1110.003"]
    elif category == "url":
        score, reasons, indicators = analyze_url_intelligence(payload)
        detection_method = "url-intelligence"
        mitre_techniques = ["T1566.002", "T1583.001"]
    elif category == "impersonation":
        score, reasons, indicators = analyze_impersonation(payload)
        detection_method = "identity-impersonation"
        mitre_techniques = ["T1036", "T1566.001"]
    elif category in {"deepfake", "image", "audio", "video"}:
        score, reasons, indicators = analyze_deepfake(payload)
        detection_method = "synthetic-media-triage"
        mitre_techniques = ["T1036", "T1585"]
    elif category in ["phishing", "email", "sms", "social"]:
        score, reasons, indicators = analyze_phishing_and_url(payload)
        detection_method = "phishing-language-and-url"
        mitre_techniques = ["T1566.001"]
    elif category in ["system_logs", "network", "api_logs", "malware", "exfiltration"]:
        score, reasons, indicators = analyze_technical_activity(payload, category)
        detection_method = "structured-flow-and-signatures" if category in {"network", "api_logs"} else "technical-signatures"
        mitre_techniques = ["T1041"] if category == "exfiltration" else ["T1190"]
    else:  # Deepfake / Image / Audio / Video default
        score, reasons, indicators = analyze_deepfake(payload)
        detection_method = "synthetic-media-triage"
        mitre_techniques = ["T1036", "T1585"]

    regional_score, regional_reasons, regional_indicators, plain_language, regional_categories = analyze_regional_scam(payload)
    if regional_score:
        score = max(score, regional_score)
        reasons.extend(regional_reasons)
        indicators.extend(regional_indicators)
        if "upi-fraud" in regional_categories:
            detection_method = f"{detection_method}+upi-fraud"
        if "digital-arrest" in regional_categories:
            detection_method = f"{detection_method}+digital-arrest"
        if regional_categories and any(language in regional_categories for language in ("Hindi/Hinglish", "Odia")):
            detection_method = f"{detection_method}+regional-language"

    model_score, model_indicator = (model_signal(payload) if category in {"email", "phishing", "sms", "social"} else (0, None))
    if model_indicator:
        indicators.append(model_indicator)
        if model_score >= TEXT_MODEL_THRESHOLD:
            score = max(score, model_score)
            reasons.append(f"Trained text classifier emitted a model score of {model_score}/100; this is not a calibrated probability.")
        
    # Risk Level Categorization Matrix
    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 40:
        level = "Medium"
    elif score >= 20:
        level = "Low"
    else:
        level = "Safe"
        
    explanation = f"{level} Risk: " + (" ".join(reasons) if reasons else "No anomalous threat signatures detected.")
    for indicator in indicators:
        indicator.setdefault("weight", max(1, round(score / max(len(indicators), 1))))
    
    actions = [{"id": "warn_user", "label": "Warn the user and verify through an official channel"}]
    if level in {"Critical", "High"}:
        actions = []
        if category == "url":
            actions.append({"id": "block_domain", "label": "Block the suspicious URL or domain"})
        elif category in {"email", "phishing"}:
            actions.extend([
                {"id": "quarantine", "label": "Quarantine the suspicious message"},
                {"id": "block_domain", "label": "Block malicious sender links and domains"},
            ])
        elif category in {"sms", "social"}:
            actions.append({"id": "warn_user", "label": "Warn recipients and report the suspicious message"})
        elif category == "deepfake":
            actions.append({"id": "quarantine", "label": "Hold media for manual authenticity review"})
        elif category == "impersonation":
            actions.append({"id": "quarantine", "label": "Preserve impersonation evidence for review"})
        elif category in {"ato", "auth_logs"}:
            actions.append({"id": "revoke_session", "label": "Revoke suspicious sessions and require re-authentication"})
        elif category == "malware":
            actions.append({"id": "quarantine", "label": "Quarantine the suspicious artifact"})
        elif category in {"network", "api_logs", "system_logs", "exfiltration", "anomaly"}:
            actions.append({"id": "escalate", "label": "Contain and investigate the technical activity"})
        actions.append({"id": "notify_soc", "label": "Notify the administrator / SOC"})
        if not any(action["id"] == "escalate" for action in actions):
            actions.append({"id": "escalate", "label": "Escalate for investigation"})
        
    return {
        "risk_score": score,
        "risk_level": level,
        "category": category,
        "xai_explanation": explanation,
        "indicators": indicators,
        "recommended_actions": actions,
        "detection_method": detection_method,
        "mitre_techniques": mitre_techniques,
        "signal_count": len(indicators),
        "explanation_summary": " ".join(reasons[:3]) or "No anomalous threat signatures detected.",
        "scoring_formula": "bounded rule evidence + modality-compatible uncalibrated model signal; final score capped at 99",
        "plain_language_explanation": plain_language or "This content did not trigger a strong scam pattern. Continue to verify unexpected requests through an official channel.",
        "regional_categories": regional_categories,
    }
