import os
from pathlib import Path
from typing import Any

MODEL_DIR = Path(os.getenv("CYBERGUARD_TEXT_TRANSFORMER_MODEL", Path(__file__).parent / "models" / "text-transformer"))
_MODEL = None
_TOKENIZER = None
_ERROR = None


def _load():
    global _MODEL, _TOKENIZER, _ERROR
    if _MODEL is not None:
        return _MODEL, _TOKENIZER
    if not MODEL_DIR.exists():
        return None, None
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        _TOKENIZER = AutoTokenizer.from_pretrained(MODEL_DIR, local_files_only=True)
        _MODEL = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR, local_files_only=True)
        _MODEL.eval()
        return _MODEL, _TOKENIZER
    except Exception as error:
        _ERROR = str(error)
        return None, None


def classify(payload: str) -> dict[str, Any] | None:
    model, tokenizer = _load()
    if model is None:
        return None
    import torch
    inputs = tokenizer(payload, return_tensors="pt", truncation=True, max_length=256)
    with torch.no_grad():
        probabilities = torch.softmax(model(**inputs).logits, dim=-1)[0]
    suspicious = float(probabilities[1])
    return {"score": round(suspicious * 100), "model": "fine-tuned DistilBERT SMS phishing classifier", "probabilities": [float(value) for value in probabilities]}


def status() -> dict[str, Any]:
    return {"configured": MODEL_DIR.exists(), "path": str(MODEL_DIR), "loaded": _MODEL is not None, "error": _ERROR, "algorithm": "fine-tuned DistilBERT"}