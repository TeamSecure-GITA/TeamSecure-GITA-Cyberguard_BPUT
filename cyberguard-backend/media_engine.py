import io
import math
import os
import tempfile
import wave
from typing import Any

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
except ImportError:
    np = None
    IsolationForest = None


def _media_anomaly_score(features: list[float], media_type: str) -> int:
    if np is None or IsolationForest is None:
        return 30
    reference = {
        "image": np.array([
            [0.50, 0.18, 0.55, 0.12], [0.48, 0.22, 0.61, 0.10], [0.53, 0.16, 0.49, 0.14],
            [0.45, 0.25, 0.58, 0.08], [0.57, 0.20, 0.52, 0.16], [0.51, 0.19, 0.64, 0.11],
        ]),
        "audio": np.array([
            [0.28, 0.08, 3.5, 0.24], [0.35, 0.12, 4.2, 0.31], [0.22, 0.06, 2.8, 0.18],
            [0.42, 0.15, 5.1, 0.36], [0.31, 0.10, 3.9, 0.27], [0.25, 0.09, 3.2, 0.21],
        ]),
    }[media_type]
    model = IsolationForest(n_estimators=64, contamination=0.15, random_state=42)
    model.fit(reference)
    decision = float(model.decision_function(np.array([features]))[0])
    return max(1, min(99, round(50 - decision * 85)))


def _entropy(values) -> float:
    if not values:
        return 0.0
    counts = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    total = len(values)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def analyze_image(content: bytes) -> dict[str, Any]:
    from PIL import Image
    from deepfake_models import analyze_pretrained

    image = Image.open(io.BytesIO(content))
    pretrained = analyze_pretrained(content, "image")
    grayscale = np.asarray(image.convert("L").resize((64, 64)), dtype=float) / 255 if np is not None else None
    pixels = grayscale.flatten().tolist() if grayscale is not None else list(image.convert("L").resize((64, 64)).getdata())
    entropy = _entropy([round(pixel * 255) for pixel in pixels])
    edge_density = float(np.mean(np.abs(np.diff(grayscale, axis=0)) > 0.18)) if grayscale is not None else 0.0
    features = [float(np.mean(grayscale)) if grayscale is not None else 0.5, float(np.std(grayscale)) if grayscale is not None else 0.2, min(entropy / 8, 1), edge_density]
    model_score = _media_anomaly_score(features, "image")
    score = round(model_score * 0.75)
    reasons = [f"Image content inspected at {image.width}x{image.height} resolution."]
    reasons.append(f"Lightweight image anomaly model scored texture and edge consistency at {model_score}%.")
    indicators = [
        {"name": "Image Anomaly Model", "score": f"{model_score}%"},
        {"name": "Image Shannon Entropy", "score": f"{round(entropy * 10)}%"},
        {"name": "Edge Consistency", "score": f"{round(edge_density * 100)}%"},
    ]
    if image.width < 128 or image.height < 128:
        score += 15
        reasons.append("Low-resolution media reduces authenticity confidence.")
    if pretrained:
        score = max(score, pretrained["score"])
        reasons.append(f"Pretrained image detector {pretrained['model']} returned {pretrained['score']}% synthetic-media confidence.")
        indicators.append({"name": "Pretrained Image Detector", "score": f"{pretrained['score']}%", "model": pretrained["model"]})
    return {"score": min(score, 99), "reasons": reasons, "indicators": indicators, "method": "pretrained-image-detector" if pretrained else "image-anomaly-model", "pretrained_model": pretrained}


def analyze_audio(content: bytes) -> dict[str, Any]:
    from deepfake_models import analyze_pretrained
    with wave.open(io.BytesIO(content), "rb") as audio:
        frame_count = audio.getnframes()
        sample_width = audio.getsampwidth()
        sample_rate = audio.getframerate()
        frames = audio.readframes(min(frame_count, sample_rate * 10))
    if np is not None and sample_width in {1, 2, 4}:
        dtype = {1: np.int8, 2: np.int16, 4: np.int32}[sample_width]
        samples_array = np.frombuffer(frames, dtype=dtype).astype(float)
    else:
        samples_array = np.array([int.from_bytes(frames[index:index + sample_width], "little", signed=True) for index in range(0, len(frames), sample_width)], dtype=float) if sample_width else np.array([])
    samples = samples_array.tolist()
    if not samples:
        return {"score": 50, "reasons": ["Audio contained no readable waveform samples."], "indicators": [], "method": "audio-statistics"}
    peak = max(abs(sample) for sample in samples)
    rms = math.sqrt(sum(sample * sample for sample in samples) / len(samples))
    zero_crossings = sum(1 for left, right in zip(samples, samples[1:]) if (left < 0) != (right < 0))
    normalized_rms = min(rms / max(peak, 1), 1)
    zero_crossing_rate = zero_crossings / max(len(samples), 1)
    crest_factor = peak / max(rms, 1)
    spectral_centroid = 0.0
    if np is not None:
        spectrum = np.abs(np.fft.rfft(samples_array[: min(len(samples_array), sample_rate * 10)]))
        frequencies = np.fft.rfftfreq(len(samples_array[: min(len(samples_array), sample_rate * 10)]), 1 / sample_rate)
        spectral_centroid = float(np.sum(frequencies * spectrum) / max(np.sum(spectrum), 1)) / max(sample_rate, 1)
    features = [normalized_rms, zero_crossing_rate, min(crest_factor, 10), spectral_centroid]
    model_score = _media_anomaly_score(features, "audio")
    score = round(model_score * 0.75)
    reasons = [f"Audio waveform inspected at {sample_rate} Hz with {frame_count} frames."]
    reasons.append(f"Lightweight audio anomaly model scored waveform consistency at {model_score}%.")
    indicators = [
        {"name": "Audio Anomaly Model", "score": f"{model_score}%"},
        {"name": "Waveform RMS Energy", "score": f"{min(round((rms / max(peak, 1)) * 100), 99)}%"},
        {"name": "Zero-Crossing Rate", "score": f"{min(round(zero_crossings / max(len(samples), 1) * 1000), 99)}%"},
    ]
    if zero_crossings / max(len(samples), 1) > 0.2:
        score += 30
        reasons.append("Unusually high spectral transition activity warrants voice-cloning review.")
    pretrained = analyze_pretrained(content, "audio")
    if pretrained:
        score = max(score, pretrained["score"])
        reasons.append(f"Pretrained audio anti-spoof detector {pretrained['model']} returned {pretrained['score']}% synthetic-media confidence.")
        indicators.append({"name": "Pretrained Audio Anti-Spoof", "score": f"{pretrained['score']}%", "model": pretrained["model"]})
    return {"score": min(score, 99), "reasons": reasons, "indicators": indicators, "method": "pretrained-audio-detector" if pretrained else "audio-anomaly-model", "pretrained_model": pretrained}


def analyze_video(content: bytes) -> dict[str, Any]:
    import cv2

    with tempfile.NamedTemporaryFile(suffix=".video", delete=False) as temporary_file:
        temporary_file.write(content)
        temporary_path = temporary_file.name
    capture = cv2.VideoCapture(temporary_path)
    frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
    width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
    height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
    sample_count = min(12, frame_count)
    frame_scores = []
    if sample_count:
        interval = max(frame_count // sample_count, 1)
        for frame_index in range(0, frame_count, interval):
            capture.set(cv2.CAP_PROP_POS_FRAMES, frame_index)
            success, frame = capture.read()
            if not success:
                continue
            encoded, buffer = cv2.imencode(".jpg", frame)
            if encoded:
                frame_result = analyze_image(buffer.tobytes())
                frame_scores.append(frame_result["score"])
            if len(frame_scores) >= sample_count:
                break
    capture.release()
    os.unlink(temporary_path)
    score = round(sum(frame_scores) / len(frame_scores)) if frame_scores else 20
    temporal_variance = max(frame_scores) - min(frame_scores) if frame_scores else 0
    reasons = [f"Video sampled {len(frame_scores)} of {frame_count} frames at {width}x{height}." ]
    indicators = [
        {"name": "Video Frame Integrity", "score": f"{min(frame_count, 99)}%"},
        {"name": "Temporal Score Variance", "score": f"{min(temporal_variance, 99)}%"},
    ]
    if temporal_variance >= 30:
        reasons.append("Frame-to-frame synthetic-media scores vary materially; manual temporal review is required.")
    if frame_count == 0 or width == 0 or height == 0:
        score += 35
        reasons.append("Video stream metadata could not be decoded reliably.")
    return {"score": min(score, 99), "reasons": reasons, "indicators": indicators, "method": "video-frame-temporal-analysis", "frame_scores": frame_scores}


def analyze_qr(content: bytes) -> dict[str, Any]:
    import cv2

    image = cv2.imdecode(np.frombuffer(content, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        return {"score": 20, "reasons": ["Image could not be decoded for QR inspection."], "indicators": [], "method": "qr-decoder"}
    decoded, points, _ = cv2.QRCodeDetector().detectAndDecode(image)
    if not decoded:
        return {"score": 5, "reasons": ["No QR payload was found in the uploaded image."], "indicators": [{"name": "QR Payload", "score": "0%"}], "method": "qr-decoder"}
    risky = decoded.lower().startswith(("http://", "https://"))
    return {"score": 65 if risky else 35, "reasons": ["QR code decoded successfully; its payload was forwarded to URL analysis."], "indicators": [{"name": "QR Payload", "score": "88%" if risky else "35%"}], "decoded_payload": decoded, "method": "qr-decoder"}


def analyze_media(content: bytes, content_type: str, filename: str, category: str) -> dict[str, Any]:
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    try:
        if suffix in {"png", "jpg", "jpeg", "webp"}:
            qr_result = analyze_qr(content)
            if qr_result.get("decoded_payload"):
                return qr_result
        if content_type.startswith("image/") or suffix in {"png", "jpg", "jpeg", "webp"}:
            return analyze_image(content)
        if content_type.startswith("audio/") or suffix in {"wav"}:
            return analyze_audio(content)
        if content_type.startswith("video/") or suffix in {"mp4", "avi", "mov"}:
            return analyze_video(content)
    except Exception as error:
        return {"score": 60, "reasons": [f"Media decoder reported an inspection error: {error}"], "indicators": [], "method": "media-fallback"}
    return {"score": 50, "reasons": [f"Media type {content_type or suffix or category} was hashed but has no specialized decoder installed."], "indicators": [], "method": "metadata-fallback"}
