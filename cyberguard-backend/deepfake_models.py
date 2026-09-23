"""Optional pretrained media detectors.

The detector is disabled unless CYBERGUARD_ENABLE_PRETRAINED_MEDIA=true. Model
weights are downloaded only by the configured Hugging Face pipeline and are
never silently substituted for the heuristic triage score.
"""
import os
import sys
import types
from pathlib import Path
from typing import Any

_IMAGE_CACHE = Path(__file__).parent / "models" / "pretrained" / "image"
_AUDIO_CACHE = Path(__file__).parent / "models" / "pretrained" / "audio"
_IMAGE_MODEL = os.getenv("CYBERGUARD_IMAGE_MODEL", str(_IMAGE_CACHE) if _IMAGE_CACHE.exists() else "dima806/deepfake_vs_real_image_detection")
_AUDIO_MODEL = os.getenv("CYBERGUARD_AUDIO_MODEL", str(_AUDIO_CACHE) if _AUDIO_CACHE.exists() else "Hemgg/Deepfake-audio-detection")
_PIPELINES: dict[str, Any] = {}
_PROCESSORS: dict[str, Any] = {}
_LOAD_ERRORS: dict[str, str] = {}


def _weights_integrity(model: str) -> dict[str, Any]:
    model_path = Path(model)
    if not model_path.is_dir():
        return {"local": False, "usable": False, "weight_bytes": 0, "reason": "remote model requires explicit download"}
    weight_files = [path for path in model_path.rglob("*") if path.is_file() and path.suffix in {".bin", ".safetensors", ".pt", ".pth"}]
    weight_bytes = sum(path.stat().st_size for path in weight_files)
    manifest = model_path / "cyberguard-manifest.json"
    return {
        "local": True,
        "usable": bool(weight_files) and weight_bytes >= 1_000_000 and manifest.exists(),
        "weight_bytes": weight_bytes,
        "manifest": str(manifest) if manifest.exists() else None,
        "reason": None if weight_files and weight_bytes >= 1_000_000 and manifest.exists() else "missing verified weight manifest or non-trivial weight artifact",
    }


def _pipeline(kind: str):
    if os.getenv("CYBERGUARD_ENABLE_PRETRAINED_MEDIA", "true").lower() not in {"1", "true", "yes"}:
        return None
    if kind in _PIPELINES:
        return _PIPELINES[kind]
    try:
        try:
            from transformers import AutoConfig, AutoImageProcessor, AutoModelForImageClassification, AutoModelForAudioClassification, AutoFeatureExtractor
        except ImportError as error:
            if "_openmp_helpers" not in str(error):
                raise
            sklearn_module = types.ModuleType("sklearn")
            metrics_module = types.ModuleType("sklearn.metrics")
            metrics_module.roc_curve = lambda *args, **kwargs: ([], [], [])
            sklearn_module.metrics = metrics_module
            previous_sklearn = sys.modules.get("sklearn")
            previous_metrics = sys.modules.get("sklearn.metrics")
            sys.modules["sklearn"] = sklearn_module
            sys.modules["sklearn.metrics"] = metrics_module
            try:
                from transformers import AutoConfig, AutoImageProcessor, AutoModelForImageClassification, AutoModelForAudioClassification, AutoFeatureExtractor
            finally:
                if previous_sklearn is None:
                    sys.modules.pop("sklearn", None)
                else:
                    sys.modules["sklearn"] = previous_sklearn
                if previous_metrics is None:
                    sys.modules.pop("sklearn.metrics", None)
                else:
                    sys.modules["sklearn.metrics"] = previous_metrics
        model = _IMAGE_MODEL if kind == "image" else _AUDIO_MODEL
        config = AutoConfig.from_pretrained(model, local_files_only=True)
        if kind == "image":
            _PROCESSORS[kind] = AutoImageProcessor.from_pretrained(model, local_files_only=True)
            _PIPELINES[kind] = AutoModelForImageClassification.from_pretrained(model, config=config, local_files_only=True)
        else:
            _PROCESSORS[kind] = AutoFeatureExtractor.from_pretrained(model, local_files_only=True)
            _PIPELINES[kind] = AutoModelForAudioClassification.from_pretrained(model, config=config, local_files_only=True)
        _PIPELINES[kind].eval()
        return _PIPELINES[kind]
    except Exception as error:
        _LOAD_ERRORS[kind] = str(error)
        return None


def analyze_pretrained(content: bytes, kind: str) -> dict[str, Any] | None:
    detector = _pipeline(kind)
    if detector is None:
        return None
    try:
        import torch
        if kind == "image":
            from PIL import Image
            import io
            inputs = _PROCESSORS[kind](images=Image.open(io.BytesIO(content)).convert("RGB"), return_tensors="pt")
        else:
            import soundfile as sf
            import io
            waveform, sample_rate = sf.read(io.BytesIO(content), dtype="float32")
            inputs = _PROCESSORS[kind](waveform, sampling_rate=sample_rate, return_tensors="pt")
        with torch.no_grad():
            logits = detector(**inputs).logits
        probabilities = torch.softmax(logits, dim=-1)[0]
        result = [{"label": detector.config.id2label.get(index, str(index)), "score": float(probabilities[index])} for index in range(len(probabilities))]
        result.sort(key=lambda item: item["score"], reverse=True)
        suspicious = [item for item in result if any(token in item["label"].lower() for token in ("fake", "spoof", "synthetic", "generated"))]
        score = round(max((float(item["score"]) for item in suspicious), default=0) * 100)
        return {"score": min(score, 99), "model": _IMAGE_MODEL if kind == "image" else _AUDIO_MODEL, "model_type": "pretrained-transformer", "predictions": result, "calibration": "model confidence; validate on an authorised holdout before production decisions"}
    except Exception as error:
        _LOAD_ERRORS[kind] = str(error)
        return None


def model_status() -> dict[str, Any]:
    enabled = os.getenv("CYBERGUARD_ENABLE_PRETRAINED_MEDIA", "true").lower() in {"1", "true", "yes"}
    integrity = {"image": _weights_integrity(_IMAGE_MODEL), "audio": _weights_integrity(_AUDIO_MODEL)}
    blocked = any("DLL load failed" in error or "Application Control" in error for error in _LOAD_ERRORS.values())
    return {"enabled": enabled, "image_model": _IMAGE_MODEL, "audio_model": _AUDIO_MODEL, "weights_cached": {kind: item["local"] for kind, item in integrity.items()}, "integrity": integrity, "loaded": sorted(_PIPELINES), "load_errors": _LOAD_ERRORS, "runtime_blocked": blocked, "mode": "pretrained" if _PIPELINES else "heuristic-fallback"}
