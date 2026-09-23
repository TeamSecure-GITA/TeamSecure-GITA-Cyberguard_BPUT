"""Versioned model metadata exposed to operators and release checks."""
import hashlib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).parent


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def model_registry() -> list[dict[str, Any]]:
    text_artifact = ROOT / "models" / "threat_text_model.joblib"
    fallback_artifact = ROOT / "models" / "threat_text_model_fallback.json"
    return [
        {
            "model_id": "cyberguard-text-phishing-v1",
            "task": "phishing / suspicious-text classification",
            "algorithm": "TF-IDF word uni/bi-grams + Logistic Regression",
            "artifact": str(text_artifact.relative_to(ROOT)),
            "artifact_hash": _sha256(text_artifact),
            "fallback_artifact": str(fallback_artifact.relative_to(ROOT)),
            "fallback_hash": _sha256(fallback_artifact),
            "training_data": "data/training_data.csv (demonstration snapshot)",
            "validation_data": "data/uci_sms_spam.csv when evaluated",
            "license": "Verify source dataset/model licence before production use",
            "limitations": "Baseline text classifier; not a universal phishing detector",
            "status": "loaded" if text_artifact.exists() else "fallback-only",
        },
        {
            "model_id": "cyberguard-media-triage-v1",
            "task": "image / audio / video synthetic-media triage",
            "algorithm": "Bounded media features with optional local transformer adapters",
            "artifact": "models/pretrained/image and models/pretrained/audio",
            "artifact_hash": None,
            "training_data": "Configured authorised media holdout required",
            "validation_data": "No production validation snapshot bundled",
            "license": "Review configured Hugging Face model licences",
            "limitations": "Triage signal only; human verification is required for consequential action",
            "status": "runtime-reported",
        },
    ]
