"""Low-confidence contact identity and writing-style comparison signals."""

from collections import Counter
from email.utils import parseaddr
import re
import unicodedata
from typing import Any


def _style_features(message: str) -> dict[str, Any]:
    words = re.findall(r"[a-z0-9']+", message.lower())
    sentences = [
        sentence for sentence in re.split(r"[.!?]+", message)
        if sentence.strip()
    ]
    sentence_lengths = [len(re.findall(r"[a-z0-9']+", sentence.lower())) for sentence in sentences]
    punctuation_count = sum(character in ".,;:!?" for character in message)
    emoji_count = sum(unicodedata.category(character) == "So" for character in message)
    word_count = max(len(words), 1)
    return {
        "average_sentence_words": sum(sentence_lengths) / max(len(sentence_lengths), 1),
        "punctuation_per_100_words": punctuation_count * 100 / word_count,
        "emoji_per_100_words": emoji_count * 100 / word_count,
        "vocabulary": Counter(words),
    }


def build_style_profile(samples: list[str]) -> dict[str, Any]:
    messages = [sample.strip() for sample in samples if isinstance(sample, str) and sample.strip()]
    if len(messages) < 3:
        raise ValueError("At least three non-empty sample messages are required.")
    features = [_style_features(message) for message in messages]
    vocabulary = Counter()
    for feature in features:
        vocabulary.update(feature["vocabulary"])
    return {
        "sample_count": len(messages),
        "average_sentence_words": sum(item["average_sentence_words"] for item in features) / len(features),
        "punctuation_per_100_words": sum(item["punctuation_per_100_words"] for item in features) / len(features),
        "emoji_per_100_words": sum(item["emoji_per_100_words"] for item in features) / len(features),
        "vocabulary": [word for word, _ in vocabulary.most_common(120)],
    }


def compare_contact_message(message: str, identifiers: list[str], profile: dict[str, Any]) -> dict[str, Any]:
    risk_score = 0
    reasons = []
    indicators = []
    sender_match = None
    from_header = re.search(r"(?im)^\s*from\s*:\s*([^\r\n]+)", message)
    if from_header:
        from_value = from_header.group(1).strip().lower()
        display_name, sender_address = parseaddr(from_value)
        display_name = display_name.strip().lower()
        sender_address = sender_address.lower()
        known_identifiers = [value.strip().lower() for value in identifiers if value.strip()]
        sender_match = any(
            identifier == sender_address if "@" in identifier else (
                identifier == display_name
                or bool(re.search(rf"(?<!\w){re.escape(identifier)}(?!\w)", display_name))
                or identifier == from_value
            )
            for identifier in known_identifiers
        )
        if not sender_match:
            risk_score += 25
            reasons.append("The message sender does not match the selected known-contact identifiers.")
            indicators.append({"name": "Known Contact Sender Mismatch", "weight": 25, "status": "mismatch"})

    message_body = re.split(r"\r?\n\r?\n", message, maxsplit=1)[-1]
    current = _style_features(message_body)
    profile_vocabulary = set(profile.get("vocabulary", []))
    current_vocabulary = set(current["vocabulary"])
    union = profile_vocabulary | current_vocabulary
    vocabulary_similarity = len(profile_vocabulary & current_vocabulary) / max(len(union), 1)
    sentence_baseline = max(float(profile.get("average_sentence_words", 0)), 1.0)
    sentence_delta = abs(current["average_sentence_words"] - sentence_baseline) / sentence_baseline
    punctuation_delta = abs(current["punctuation_per_100_words"] - float(profile.get("punctuation_per_100_words", 0)))
    emoji_delta = abs(current["emoji_per_100_words"] - float(profile.get("emoji_per_100_words", 0)))
    style_deviations = []

    if len(current["vocabulary"]) >= 8 and len(profile_vocabulary) >= 8 and vocabulary_similarity < 0.18:
        style_deviations.append(("Vocabulary differs substantially from the known-contact samples.", 15, "Known Contact Vocabulary Deviation"))
    if len(current["vocabulary"]) >= 8 and sentence_delta >= 0.75:
        style_deviations.append(("Average sentence length differs substantially from the known-contact samples.", 10, "Known Contact Sentence-Style Deviation"))
    if len(current["vocabulary"]) >= 8 and punctuation_delta >= 1.5:
        style_deviations.append(("Punctuation frequency differs from the known-contact samples.", 8, "Known Contact Punctuation Deviation"))
    if len(current["vocabulary"]) >= 8 and emoji_delta >= 1.0:
        style_deviations.append(("Emoji frequency differs from the known-contact samples.", 8, "Known Contact Emoji Deviation"))

    for reason, weight, name in style_deviations:
        risk_score += weight
        reasons.append(reason)
        indicators.append({"name": name, "weight": weight, "status": "deviation"})

    return {
        "risk_score": min(risk_score, 50),
        "sender_match": sender_match,
        "vocabulary_similarity": round(vocabulary_similarity, 3),
        "sample_count": int(profile.get("sample_count", 0)),
        "reasons": reasons,
        "indicators": indicators,
        "caveat": "Contact and writing-style differences are review signals, not proof of impersonation.",
    }