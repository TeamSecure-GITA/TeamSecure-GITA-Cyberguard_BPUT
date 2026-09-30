import re
from typing import Any


def analyze_regional_scam(payload: str) -> tuple[int, list[str], list[dict[str, Any]], str | None, list[str]]:
    text = payload.lower()
    indicators: list[dict[str, Any]] = []
    reasons: list[str] = []
    categories: list[str] = []
    score = 0
    upi_signals = {
        "payment service": r"\b(?:upi|gpay|google pay|phonepe|paytm|bhim)\b",
        "payment collection": r"\b(?:collect request|request money|scan (?:the )?qr|qr code)\b",
        "credential request": r"\b(?:upi pin|otp|one[- ]time password|share your pin|share your password)\b",
        "payment coercion": r"\b(?:pay now|send money|cashback|refund|prize|reward|account.{0,20}(?:blocked|suspended)|kyc.{0,20}(?:blocked|suspended|expire))\b",
    }
    matched_upi = [name for name, pattern in upi_signals.items() if re.search(pattern, text)]
    if len(matched_upi) >= 2 or re.search(r"\b(?:upi pin|collect request)\b", text):
        for name in matched_upi:
            score += 20
            reasons.append(f"Digital-payment scam signal detected: {name}.")
            indicators.append({"name": name.title(), "score": "88%", "weight": 20})
        categories.append("upi-fraud")

    arrest_signals = {
        "authority claim": r"\b(?:police|cbi|customs|income tax|court|cyber crime|rbi|government|officer|inspector)\b",
        "arrest threat": r"\b(?:digital arrest|arrested|detention|jail|case registered|warrant)\b",
        "call-control pressure": r"\b(?:do not disconnect|stay on (?:the )?call|video call.{0,30}(?:arrest|detention))\b",
        "payment or credential demand": r"\b(?:pay (?:now|a fee|the amount)|transfer (?:money|funds)|send money|share (?:your )?(?:otp|pin|password))\b",
    }
    matched_arrest = [name for name, pattern in arrest_signals.items() if re.search(pattern, text)]
    if "arrest threat" in matched_arrest or len(matched_arrest) >= 2:
        for name in matched_arrest:
            score += 20
            reasons.append(f"Fake-authority call signal detected: {name}.")
            indicators.append({"name": name.title(), "score": "92%", "weight": 20})
        categories.append("digital-arrest")

    regional_patterns = {
        "Hindi/Hinglish": r"\b(?:aapka account.{0,30}(?:band|block|freeze)|giraftar|paise bhejo|otp batao|police station)\b",
        "Odia": r"(?:ଖାତା.{0,30}(?:ବନ୍ଦ|ବ୍ଲକ)|ଗିରଫ|ଟଙ୍କା.{0,20}(?:ପଠା|ଦିଅ)|ଓଟିପି.{0,20}(?:ଦିଅ|କୁହ))",
    }
    languages = []
    for language, pattern in regional_patterns.items():
        if re.search(pattern, text):
            languages.append(language)
            score += 15
            reasons.append(f"{language} scam-language pattern detected; verify through an official channel.")
            indicators.append({"name": f"{language} Scam Language", "score": "78%", "weight": 15})
    if not reasons:
        return 0, [], [], None, []
    if "upi-fraud" in categories and "digital-arrest" in categories:
        plain = "This message is pressuring you to send money while pretending to be an official service. Do not pay, share an OTP, or scan the QR code."
    elif "upi-fraud" in categories:
        plain = "This message may be a fake payment or refund request. Do not scan the QR code or share your UPI PIN or OTP."
    elif "digital-arrest" in categories:
        plain = "This caller may be pretending to be the police or another authority. Real officials do not put people under digital arrest or demand payment on a video call."
    else:
        plain = "This message uses regional scam language and needs verification through a trusted official channel."
    return min(score, 99), reasons, indicators, plain, sorted(set(categories + languages))
