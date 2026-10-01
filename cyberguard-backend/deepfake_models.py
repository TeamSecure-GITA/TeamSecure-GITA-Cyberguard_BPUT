"""Optional pretrained media detectors.

The detector is disabled unless CYBERGUARD_ENABLE_PRETRAINED_MEDIA=true. Model
weights are downloaded only by the configured Hugging Face pipeline and are
never silently substituted for the heuristic triage score.
"""
import os
import re
import sys
import types
import math
from pathlib import Path
from typing import Any

_IMAGE_CACHE = Path(__file__).parent / "models" / "pretrained" / "image"
_AUDIO_CACHE = Path(__file__).parent / "models" / "pretrained" / "audio"
_IMAGE_MODEL = os.getenv("CYBERGUARD_IMAGE_MODEL", str(_IMAGE_CACHE) if _IMAGE_CACHE.exists() else "dima806/deepfake_vs_real_image_detection")
_AUDIO_MODEL = os.getenv("CYBERGUARD_AUDIO_MODEL", str(_AUDIO_CACHE) if _AUDIO_CACHE.exists() else "Hemgg/Deepfake-audio-detection")
_PIPELINES: dict[str, Any] = {}
_PROCESSORS: dict[str, Any] = {}
_LOAD_ERRORS: dict[str, str] = {}
SUSPICIOUS_LABEL_TOKENS = {"fake", "spoof", "synthetic", "generated", "ai", "aivoice", "deepfake", "manipulated", "artificial", "clone", "cloned"}


def _is_suspicious_label(label: str) -> bool:
    tokens = set(re.findall(r"[a-z0-9]+", label.lower()))
    return bool(tokens & SUSPICIOUS_LABEL_TOKENS)


def _prepare_audio_waveform(waveform, sample_rate: int, target_sample_rate: int):
    import numpy as np

    if sample_rate <= 0 or target_sample_rate <= 0:
        raise ValueError("Audio sample rates must be positive")
    samples = np.asarray(waveform, dtype=np.float32)
    if samples.ndim > 1:
        samples = samples.mean(axis=1)
    if sample_rate != target_sample_rate:
        from scipy.signal import resample_poly

        divisor = math.gcd(sample_rate, target_sample_rate)
        samples = resample_poly(samples, target_sample_rate // divisor, sample_rate // divisor).astype(np.float32)
    return samples, target_sample_rate


def _weight_status(model: str) -> dict[str, Any]:
    model_path = Path(model)
    if not model_path.is_dir():
        return {"cached": False, "reason": "model files are not present in a local directory"}
    weight_files = [*model_path.glob("*.safetensors"), *model_path.glob("pytorch_model*.bin")]
    if not weight_files:
        return {"cached": False, "reason": "no supported model weight file found"}
    for weight_file in weight_files:
        if weight_file.stat().st_size < 1_000_000:
            with weight_file.open("rb") as stream:
                header = stream.read(256)
            if header.startswith(b"version https://git-lfs.github.com/spec/v1"):
                return {"cached": False, "reason": "Git-LFS pointer", "file": weight_file.name}
            return {"cached": False, "reason": "weight file is smaller than 1 MB", "file": weight_file.name}
    return {"cached": True, "reason": None}


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
        if Path(model).is_dir():
            weight_status = _weight_status(model)
            if not weight_status["cached"]:
                raise RuntimeError(weight_status["reason"])
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
            import numpy as np
            import soundfile as sf
            import io
            waveform, sample_rate = sf.read(io.BytesIO(content), dtype="float32", always_2d=True)
            target_sample_rate = int(getattr(_PROCESSORS[kind], "sampling_rate", None) or sample_rate)
            waveform, sample_rate = _prepare_audio_waveform(waveform, sample_rate, target_sample_rate)
            inputs = _PROCESSORS[kind](waveform, sampling_rate=sample_rate, return_tensors="pt")
        with torch.no_grad():
            logits = detector(**inputs).logits
        probabilities = torch.softmax(logits, dim=-1)[0]
        result = [{"label": detector.config.id2label.get(index, str(index)), "score": float(probabilities[index])} for index in range(len(probabilities))]
        result.sort(key=lambda item: item["score"], reverse=True)
        for item in result:
            item["is_suspicious"] = _is_suspicious_label(item["label"])
        suspicious = [item for item in result if item["is_suspicious"]]
        score = round(max((float(item["score"]) for item in suspicious), default=0) * 100)
        return {"score": min(score, 99), "model": _IMAGE_MODEL if kind == "image" else _AUDIO_MODEL, "model_type": "pretrained-transformer", "predictions": result, "calibration": "model confidence; validate on an authorised holdout before production decisions"}
    except Exception as error:
        _LOAD_ERRORS[kind] = str(error)
        return None


def model_status() -> dict[str, Any]:
    enabled = os.getenv("CYBERGUARD_ENABLE_PRETRAINED_MEDIA", "true").lower() in {"1", "true", "yes"}
    image_weights = _weight_status(_IMAGE_MODEL)
    audio_weights = _weight_status(_AUDIO_MODEL)
    weight_status = {"image": image_weights, "audio": audio_weights}
    cached = {kind: status["cached"] for kind, status in weight_status.items()}
    blocked = any("DLL load failed" in error or "Application Control" in error for error in _LOAD_ERRORS.values())
    if not enabled:
        mode = "disabled"
    elif _PIPELINES:
        mode = "pretrained-loaded"
    elif any(status["reason"] == "Git-LFS pointer" for status in weight_status.values()):
        mode = "invalid-weights"
    elif _LOAD_ERRORS:
        mode = "load-failed"
    elif all(cached.values()):
        mode = "pretrained-cached"
    else:
        mode = "weights-not-cached"
    return {"enabled": enabled, "image_model": _IMAGE_MODEL, "audio_model": _AUDIO_MODEL, "weights_cached": cached, "weight_status": weight_status, "loaded": sorted(_PIPELINES), "load_errors": _LOAD_ERRORS, "runtime_blocked": blocked, "mode": mode, "heuristic_fallback": mode != "pretrained-loaded"}
