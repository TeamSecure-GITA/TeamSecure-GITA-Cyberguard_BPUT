import re
from typing import Any


def analyze_regional_scam(payload: str) -> tuple[int, list[str], list[dict[str, Any]], str | None, list[str]]:
    text = payload.lower()
    indicators: list[dict[str, Any]] = []
    reasons: list[str] = []
    categories: list[str] = []
    score = 0
    upi_patterns = {
        "upi collect request": r"upi|gpay|google pay|phonepe|paytm|bhim|collect request|scan.*qr|qr.*scan|@upi",
        "payment pressure": r"refund|cashback|kyc|payment|transfer|send money|pay now|₹|rs\.?\s*\d+|inr\s*\d+",
    }
    for name, pattern in upi_patterns.items():
        if re.search(pattern, text):
            score += 24
            categories.append("upi-fraud")
            reasons.append(f"Digital-payment scam signal detected: {name}.")
            indicators.append({"name": name.title(), "score": "88%", "weight": 24})
    arrest_patterns = {
        "fake authority": r"police|cbi|customs|income tax|court|cyber crime|rbi|government|officer|inspector",
        "digital arrest pressure": r"digital arrest|video call.*arrest|arrested|detention|jail|case registered|warrant",
        "secrecy and urgency": r"do not disconnect|stay on.*call|urgent|immediately|within \d+ hours",
    }
    for name, pattern in arrest_patterns.items():
        if re.search(pattern, text):
            score += 24
            categories.append("digital-arrest")
            reasons.append(f"Fake-authority call signal detected: {name}.")
            indicators.append({"name": name.title(), "score": "92%", "weight": 24})
    regional_patterns = {
        "Hindi/Hinglish": r"aapka account|turant|jaldi|police station|giraftar|kyc update|paise bhejo|otp batao",
        "Odia": r"ଖାତା|ତୁରନ୍ତ|ପୋଲିସ|ଗିରଫ|ଟଙ୍କା|ଓଟିପି",
    }
    languages = []
    for language, pattern in regional_patterns.items():
        if re.search(pattern, text):
            languages.append(language)
            score += 12
            reasons.append(f"{language} scam-language pattern detected; verify through an official channel.")
            indicators.append({"name": f"{language} Scam Language", "score": "78%", "weight": 12})
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
