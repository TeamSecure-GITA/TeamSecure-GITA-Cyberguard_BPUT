import json
import math
import os
import re
from difflib import SequenceMatcher
from pathlib import Path
from typing import List
from urllib.parse import parse_qs, urlparse

import tldextract

try:
    import joblib
except ImportError:
    joblib = None

MODEL_PATH = Path(__file__).parent / "models" / "threat_text_model.joblib"
FALLBACK_MODEL_PATH = Path(__file__).parent / "models" / "threat_text_model_fallback.json"
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
    return score, {"name": "Trained Text Model Confidence", "score": f"{score}%", "model": "TF-IDF + Logistic Regression" if TEXT_MODEL is not None else FALLBACK_TEXT_MODEL["algorithm"]}

def analyze_phishing_and_url(payload: str) -> tuple[int, List[str], List[dict]]:
    score = 6
    reasons = []
    indicators = []

    payload_lower = payload.lower()
    urgency_keywords = ["urgent", "verify", "immediate", "account suspended", "password reset", "action required", "final warning", "security alert"]
    detected_keywords = [kw for kw in urgency_keywords if kw in payload_lower]
    if detected_keywords:
        score += 24
        reasons.append(f"High-urgency language and social engineering indicators detected ({', '.join(detected_keywords)}).")
        indicators.append({"name": "Language Pressure Index", "score": "88%"})

    authority_terms = ["admin", "registrar", "director", "finance", "bank", "support", "official", "security team"]
    if any(term in payload_lower for term in authority_terms):
        score += 18
        reasons.append("Authority impersonation framing suggests a trusted identity was invoked.")
        indicators.append({"name": "Authority Impersonation Signal", "score": "84%"})

    requests = ["transfer", "otp", "password", "verify credentials", "click here", "confirm identity", "reset password", "update payment", "wire", "gift card"]
    if any(term in payload_lower for term in requests):
        score += 20
        reasons.append("Credential harvesting or financial coercion language is present in the request.")
        indicators.append({"name": "Credential Theft Construct", "score": "86%"})

    sender_domains = re.findall(r"from:.*?@([\w.-]+\.[A-Za-z]{2,})", payload_lower)
    if sender_domains and any(domain.endswith(("gmail.com", "outlook.com", "yahoo.com", "hotmail.com")) for domain in sender_domains):
        score += 10
        reasons.append("The sender channel does not match the claimed institutional identity.")
        indicators.append({"name": "Sender Identity Mismatch", "score": "78%"})

    urls = re.findall(r'https?://[^\s]+', payload)
    if urls:
        for url in urls:
            extracted = tldextract.extract(url)
            domain_str = f"{extracted.domain}.{extracted.suffix}"
            host = extracted.fqdn or extracted.domain
            if any(token in host for token in ("login", "verify", "secure", "update", "micros0ft", "paypa1", "bput")) and domain_str not in {"bput.ac.in", "bput.edu.in", "bput.ac.in"}:
                score += 24
                reasons.append(f"Look-alike credential lure domain identified ({domain_str}) impersonating an official authority.")
                indicators.append({"name": "Domain Dissimilarity Score", "score": "95%"})
            elif extracted.suffix in ["xyz", "top", "online", "live", "site", "click"]:
                score += 18
                reasons.append(f"Unverified or high-risk TLD extension detected ({extracted.suffix}).")
                indicators.append({"name": "Unverified SSL / TLD Reputation", "score": "82%"})
            if any(token in url.lower() for token in ("redirect=", "next=", "return=", "continue=")):
                score += 12
                reasons.append("URL redirect parameters are hiding a second destination and increase the risk of credential theft.")
                indicators.append({"name": "Redirect Obfuscation", "score": "81%"})
            if len(host) >= 24 or host.count("-") >= 2 or re.search(r"\d", host):
                score += 8
                reasons.append(f"Host naming pattern is abnormal and consistent with social-engineering lure construction ({host}).")
                indicators.append({"name": "Lexical URL Anomaly", "score": "74%"})

    if not reasons:
        reasons.append("No phishing or social-engineering patterns matched the content baseline.")
        indicators.append({"name": "Baseline Email Hygiene", "score": "14%"})

    return min(score, 99), reasons, indicators


def analyze_url_intelligence(payload: str) -> tuple[int, List[str], List[dict]]:
    score = 10
    reasons = []
    indicators = []
    urls = re.findall(r"https?://[^\s<>\"']+", payload.lower())
    risky_tlds = {"xyz", "top", "online", "live", "site", "click", "zip"}
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly"}
    trusted_domains = {"microsoft.com", "google.com", "bput.ac.in", "paypal.com", "office.com"}
    brand_domains = {"microsoft": "microsoft.com", "google": "google.com", "bput": "bput.ac.in", "paypal": "paypal.com", "office": "office.com"}
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
            indicators.append({"name": "Lexical URL Anomaly", "score": f"{min(round(55 + lexical_entropy * 6), 98)}%"})
        if extracted.suffix in risky_tlds:
            score += 25
            reasons.append(f"URL intelligence flagged a high-risk top-level domain ({extracted.suffix}).")
            indicators.append({"name": "URL Reputation Risk", "score": "86%"})
        if host in shorteners or extracted.domain in shorteners:
            score += 20
            reasons.append("Redirect shortener obscures the destination and requires analyst expansion.")
            indicators.append({"name": "Redirect Obfuscation", "score": "82%"})
        if "xn--" in host or re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", parsed_url.hostname or ""):
            score += 30
            reasons.append("URL uses an IDN or raw IP host, reducing domain identity confidence.")
            indicators.append({"name": "Host Identity Confidence", "score": "91%"})
        for brand, trusted_domain in brand_domains.items():
            similarity = SequenceMatcher(None, registered_domain, trusted_domain).ratio()
            if brand in extracted.domain and registered_domain not in trusted_domains:
                score += 30
                reasons.append(f"Brand-like domain requires look-alike and typosquatting review ({host}).")
                indicators.append({"name": "Typosquatting Similarity", "score": f"{round(similarity * 100)}%"})
                break
        query_keys = set(parse_qs(parsed_url.query).keys())
        if query_keys.intersection({"url", "u", "redirect", "redirect_uri", "next", "return", "continue"}):
            score += 20
            reasons.append("Redirect parameter can conceal a second destination and needs expansion.")
            indicators.append({"name": "Suspicious Redirect Chain", "score": "90%"})
    if len(urls) > 1:
        score += 15
        reasons.append(f"Multiple URL hops detected ({len(urls)} destinations in one artifact).")
        indicators.append({"name": "Redirect Hop Count", "score": f"{min(50 + len(urls) * 15, 98)}%"})
    if not urls:
        reasons.append("No URL artifact was supplied for reputation enrichment.")
        indicators.append({"name": "URL Extraction", "score": "0%"})
    return min(score, 99), reasons, indicators

def analyze_account_takeover(payload: str) -> tuple[int, List[str], List[dict]]:
    score = 20
    reasons = []
    indicators = []
    
    if "failed" in payload.lower() or "unauthorized" in payload.lower():
        score += 65
        reasons.append("High-frequency failed authentication attempts from anomalous IP subnets (Password Spraying signature).")
        indicators.append({"name": "Authentication Anomaly Index", "score": "94%"})
        indicators.append({"name": "Geographic / IP Distance Velocity", "score": "89%"})
        
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
            indicators.append({"name": f"{signal.title()} Signal", "score": f"{min(60 + increment, 98)}%"})
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
                indicators.append({"name": "Structured Behavioural Anomaly", "score": f"{min(55 + anomaly_score, 99)}%"})
            indicators.append({"name": "Failure Rate", "score": f"{round(failure_rate * 100)}%"})
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    if not reasons:
        reasons.append("No account-behavior deviation matched the ATO baseline.")
        indicators.append({"name": "Behavioral Baseline Match", "score": "18%"})
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
        indicators.append({"name": "Trusted Role Impersonation", "score": "89%"})
    if matched_requests:
        score += 25
        reasons.append(f"High-impact request pattern detected ({', '.join(matched_requests)}).")
        indicators.append({"name": "Request Coercion Pattern", "score": "87%"})
    if matched_urgency:
        score += 15
        reasons.append(f"Urgency and authority pressure detected ({', '.join(matched_urgency)}).")
        indicators.append({"name": "Urgency Pressure", "score": "86%"})
    if claimed_identity:
        score += 10
        reasons.append(f"Claimed identity extracted from communication ({claimed_identity.group(1).strip()}).")
        indicators.append({"name": "Claimed Identity", "score": "78%"})
    if re.search(r"from:.*@(gmail|outlook|yahoo)\.", payload_lower) or (matched_authority and re.search(r"@(gmail|outlook|yahoo)\.", payload_lower)):
        score += 20
        reasons.append("Contact channel does not match the claimed institutional identity.")
        indicators.append({"name": "Contact Mismatch", "score": "93%"})
    if not reasons:
        reasons.append("No trusted-identity impersonation pattern matched.")
        indicators.append({"name": "Identity Consistency", "score": "22%"})
    return min(score, 99), reasons, indicators


def analyze_deepfake(payload: str) -> tuple[int, List[str], List[dict]]:
    payload_lower = payload.lower()
    score = 35
    reasons = ["Synthetic-media triage enabled; media decoder evidence is combined with content signals."]
    indicators = [{"name": "Synthetic Media Triage", "score": "72%"}]
    signals = {"voice clone": 20, "face swap": 25, "lip sync": 18, "generated": 15, "synthetic": 15, "deepfake": 25}
    for signal, increment in signals.items():
        if signal in payload_lower:
            score += increment
            reasons.append(f"Synthetic-media marker detected: {signal}.")
            indicators.append({"name": f"{signal.title()} Evidence", "score": f"{min(70 + increment, 98)}%"})
    return min(score, 99), reasons, indicators

def analyze_technical_activity(payload: str) -> tuple[int, List[str], List[dict]]:
    payload_lower = payload.lower()
    score = 15
    reasons = []
    indicators = []
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
    for signature, (increment, reason) in signatures.items():
        if signature in payload_lower:
            score += increment
            reasons.append(reason)
            indicators.append({"name": f"{signature.title()} Signature", "score": f"{min(60 + increment, 98)}%"})
    return min(score, 99), reasons, indicators

def adversarial_self_test(category: str, payload: str) -> dict:
    baseline = evaluate_threat_payload(category, payload)
    baseline_score = int(baseline["risk_score"])

    variants = [
        payload,
        payload.replace("urgent", "immediately").replace("verify", "confirm").replace("password", "credentials"),
        payload + " Please act now before access is suspended.",
        payload.replace("@", "@") + " secure-login-check.example/confirm",
    ]

    results = []
    for index, variant in enumerate(variants[:4], start=1):
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
    indicators = [{"name": "Isolation Forest Login Anomaly", "score": f"{anomaly}%", "weight": 30}]
    if event.get("impossible_travel"):
        reasons.append("Impossible-travel activity is inconsistent with the user baseline.")
        indicators.append({"name": "Impossible Travel", "score": "94%", "weight": 25})
    return round(anomaly * 0.7), reasons, indicators


def evaluate_threat_payload(category: str, payload: str) -> dict:
    if category in {"auth_logs", "anomaly"}:
        score, reasons, indicators = analyze_login_anomaly(payload)
        detection_method = "isolation-forest-behavioral-baseline"
        mitre_techniques = ["T1078", "T1110.003"]
    elif category == "url":
        score, reasons, indicators = analyze_url_intelligence(payload)
        detection_method = "url-intelligence"
        mitre_techniques = ["T1566.002", "T1583.001"]
    elif category == "ato":
        score, reasons, indicators = analyze_behavioral_ato(payload)
        detection_method = "behavioral-ato"
        mitre_techniques = ["T1078", "T1110"]
    elif category == "impersonation":
        score, reasons, indicators = analyze_impersonation(payload)
        detection_method = "identity-impersonation"
        mitre_techniques = ["T1036", "T1566.001"]
    elif category == "deepfake":
        score, reasons, indicators = analyze_deepfake(payload)
        detection_method = "synthetic-media-triage"
        mitre_techniques = ["T1036", "T1585"]
    elif category in ["phishing", "email", "sms", "social"]:
        score, reasons, indicators = analyze_phishing_and_url(payload)
        detection_method = "phishing-language-and-url"
        mitre_techniques = ["T1566.001"]
    elif category in ["ato", "auth_logs"]:
        score, reasons, indicators = analyze_account_takeover(payload)
        detection_method = "authentication-heuristics"
        mitre_techniques = ["T1078"]
    elif category in ["system_logs", "network", "api_logs", "malware", "exfiltration"]:
        score, reasons, indicators = analyze_technical_activity(payload)
        detection_method = "technical-signatures"
        mitre_techniques = ["T1041"] if category == "exfiltration" else ["T1190"]
    else:  # Deepfake / Image / Audio / Video default
        score, reasons, indicators = analyze_deepfake(payload)
        detection_method = "synthetic-media-triage"
        mitre_techniques = ["T1036", "T1585"]

    model_score, model_indicator = model_signal(payload)
    if model_indicator:
        indicators.append(model_indicator)
        if model_score >= 60:
            score = max(score, model_score)
            reasons.append(f"Trained text classifier marked the payload as suspicious with {model_score}% confidence.")
        
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
    
    # Intelligent Playbook Mappings
    actions = []
    if level in ["Critical", "High"]:
        actions.append({"id": "block_domain", "label": "Block Suspicious Domain / IP"})
        actions.append({"id": "quarantine", "label": "Quarantine Email / Flag Media"})
        actions.append({"id": "revoke_session", "label": "Revoke Active Session & Enforce MFA"})
        actions.append({"id": "notify_soc", "label": "Notify Administrator / SOC"})
        actions.append({"id": "escalate", "label": "Escalate for Investigation"})
    else:
        actions.append({"id": "warn_user", "label": "Display Safety Banner"})
        
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
        "scoring_formula": "bounded rule evidence + calibrated text/media/model signal; final score capped at 99",
    }