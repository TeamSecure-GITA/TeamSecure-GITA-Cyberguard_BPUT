import io
from importlib.util import find_spec
import math
import os
import shutil
import statistics
import subprocess
import tempfile
import wave
from typing import Any

AUDIO_SUFFIXES = {"wav", "flac", "ogg", "oga", "aiff", "aif", "mp3", "m4a", "aac"}
VIDEO_AUDIO_MAX_SECONDS = 10
VIDEO_AUDIO_TIMEOUT_SECONDS = 20
VIDEO_FRAME_MAX_EDGE = 960
VIDEO_FRAME_MAX_PIXELS = 12_000_000

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
except ImportError:
    np = None
    IsolationForest = None


def media_inspection_status() -> dict[str, Any]:
    dependencies = {
        "numpy": np is not None,
        "isolation_forest": IsolationForest is not None,
        "pillow": find_spec("PIL") is not None,
        "opencv": find_spec("cv2") is not None,
    }
    available = all(dependencies.values())
    return {
        "available": available,
        "loaded": False,
        "mode": "on-demand-heuristic" if available else "limited-fallback",
        "algorithm": "Isolation Forest over image/audio features plus sampled frames and optional video audio" if available else "metadata and rule fallback",
        "dependencies": dependencies,
        "optional_dependencies": {"ffmpeg": shutil.which("ffmpeg") is not None},
    }


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
    reasons.append(f"Lightweight image anomaly model output: {model_score}/99 for texture and edge consistency.")
    indicators = [
        {"name": "Image Anomaly Model", "model_output": model_score, "weight": max(1, score)},
        {"name": "Image Shannon Entropy", "observed_bits": round(entropy, 3), "weight": 1},
        {"name": "Edge Consistency", "observed_density": round(edge_density, 4), "weight": 1},
    ]
    if image.width < 128 or image.height < 128:
        score += 15
        reasons.append("Low-resolution media reduces authenticity confidence.")
    if pretrained:
        score = max(score, pretrained["score"])
        reasons.append(f"Pretrained image detector {pretrained['model']} returned model score {pretrained['score']}/99; this is not a calibrated probability.")
        indicators.append({"name": "Pretrained Image Detector", "model_output": pretrained["score"], "weight": max(1, pretrained["score"]), "model": pretrained["model"]})
    return {"score": min(score, 99), "reasons": reasons, "indicators": indicators, "method": "pretrained-image-detector" if pretrained else "image-anomaly-model", "pretrained_model": pretrained}


def analyze_audio(content: bytes) -> dict[str, Any]:
    from deepfake_models import analyze_pretrained
    try:
        import soundfile as sf
        audio_info = sf.info(io.BytesIO(content))
        frame_count = int(audio_info.frames)
        sample_rate = int(audio_info.samplerate)
        frames, _ = sf.read(io.BytesIO(content), frames=min(frame_count, sample_rate * 10), dtype="float32", always_2d=True)
        samples_array = frames.mean(axis=1).astype(float) if np is not None else [sum(frame) / len(frame) for frame in frames]
    except (ImportError, RuntimeError, ValueError):
        with wave.open(io.BytesIO(content), "rb") as audio:
            frame_count = audio.getnframes()
            sample_width = audio.getsampwidth()
            sample_rate = audio.getframerate()
            frames = audio.readframes(min(frame_count, sample_rate * 10))
        if np is not None and sample_width in {1, 2, 4}:
            dtype = {1: np.uint8, 2: np.int16, 4: np.int32}[sample_width]
            samples_array = np.frombuffer(frames, dtype=dtype).astype(float)
            if sample_width == 1:
                samples_array -= 128
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
    reasons.append(f"Lightweight audio anomaly model output: {model_score}/99 for waveform consistency.")
    indicators = [
        {"name": "Audio Anomaly Model", "model_output": model_score, "weight": max(1, score)},
        {"name": "Waveform RMS Energy", "observed_fraction": round(rms / max(peak, 1), 4), "weight": 1},
        {"name": "Zero-Crossing Rate", "observed_rate": round(zero_crossings / max(len(samples), 1), 5), "weight": 1},
    ]
    if zero_crossings / max(len(samples), 1) > 0.2:
        score += 30
        reasons.append("Unusually high spectral transition activity warrants voice-cloning review.")
    pretrained = analyze_pretrained(content, "audio")
    if pretrained:
        score = max(score, pretrained["score"])
        reasons.append(f"Pretrained audio anti-spoof detector {pretrained['model']} returned model score {pretrained['score']}/99; this is not a calibrated probability.")
        indicators.append({"name": "Pretrained Audio Anti-Spoof", "model_output": pretrained["score"], "weight": max(1, pretrained["score"]), "model": pretrained["model"]})
    return {"score": min(score, 99), "reasons": reasons, "indicators": indicators, "method": "pretrained-audio-detector" if pretrained else "audio-anomaly-model", "pretrained_model": pretrained}


def _analyze_video_audio(video_path: str) -> dict[str, Any]:
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        return {
            "status": "unavailable",
            "reason": "FFmpeg is not installed; the video's audio track was not analyzed.",
            "max_seconds": VIDEO_AUDIO_MAX_SECONDS,
        }

    try:
        result = subprocess.run(
            [
                ffmpeg,
                "-hide_banner",
                "-loglevel", "error",
                "-nostdin",
                "-i", video_path,
                "-map", "0:a:0",
                "-vn",
                "-t", str(VIDEO_AUDIO_MAX_SECONDS),
                "-ac", "1",
                "-ar", "16000",
                "-c:a", "pcm_s16le",
                "-f", "wav",
                "pipe:1",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=VIDEO_AUDIO_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "reason": f"Audio extraction exceeded the {VIDEO_AUDIO_TIMEOUT_SECONDS}-second time limit.",
            "max_seconds": VIDEO_AUDIO_MAX_SECONDS,
        }
    except OSError as error:
        return {
            "status": "failed",
            "reason": f"FFmpeg could not be started ({error.__class__.__name__}); the audio track was not analyzed.",
            "max_seconds": VIDEO_AUDIO_MAX_SECONDS,
        }

    if result.returncode != 0 or not result.stdout:
        return {
            "status": "failed",
            "reason": "FFmpeg could not decode an audio track; the video may have no audio or an unsupported audio stream.",
            "max_seconds": VIDEO_AUDIO_MAX_SECONDS,
        }

    try:
        assessment = analyze_audio(result.stdout)
    except (OSError, RuntimeError, ValueError, EOFError, wave.Error, ImportError) as error:
        return {
            "status": "failed",
            "reason": f"Extracted audio could not be analyzed ({error.__class__.__name__}).",
            "max_seconds": VIDEO_AUDIO_MAX_SECONDS,
        }
    return {
        "status": "analyzed",
        "score": assessment["score"],
        "method": assessment["method"],
        "reasons": assessment["reasons"],
        "indicators": assessment["indicators"],
        "pretrained_model": assessment.get("pretrained_model"),
        "max_seconds": VIDEO_AUDIO_MAX_SECONDS,
    }


def analyze_video(content: bytes) -> dict[str, Any]:
    import cv2
    from deepfake_models import analyze_pretrained

    with tempfile.NamedTemporaryFile(suffix=".video", delete=False) as temporary_file:
        temporary_file.write(content)
        temporary_path = temporary_file.name
    sampled_frames = []
    frame_sampling_status = "analyzed"
    frame_sampling_reason = None
    capture = None
    video_audio = {
        "status": "unavailable",
        "reason": "Video audio was not analyzed.",
        "max_seconds": VIDEO_AUDIO_MAX_SECONDS,
    }
    try:
        capture = cv2.VideoCapture(temporary_path)
        frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
        height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
        if width <= 0 or height <= 0:
            frame_sampling_status = "unavailable"
            frame_sampling_reason = "Video frame dimensions could not be decoded reliably."
        elif width * height > VIDEO_FRAME_MAX_PIXELS:
            frame_sampling_status = "skipped"
            frame_sampling_reason = (
                f"Frame sampling was skipped because {width}x{height} exceeds the "
                f"{VIDEO_FRAME_MAX_PIXELS:,}-pixel per-frame limit."
            )
        elif frame_count <= 0:
            frame_sampling_status = "unavailable"
            frame_sampling_reason = "Video frame count could not be decoded reliably."
        else:
            sample_count = min(frame_count, 30)
            frame_indices = sorted({
                round(index * (frame_count - 1) / max(sample_count - 1, 1))
                for index in range(sample_count)
            })
            for frame_index in frame_indices:
                capture.set(cv2.CAP_PROP_POS_FRAMES, frame_index)
                ok, frame = capture.read()
                if ok:
                    frame_height, frame_width = frame.shape[:2]
                    if frame_width * frame_height > VIDEO_FRAME_MAX_PIXELS:
                        frame_sampling_status = "skipped"
                        frame_sampling_reason = (
                            f"Frame sampling stopped because a decoded frame exceeded "
                            f"the {VIDEO_FRAME_MAX_PIXELS:,}-pixel per-frame limit."
                        )
                        sampled_frames.clear()
                        break
                    scale = min(1.0, VIDEO_FRAME_MAX_EDGE / max(frame_width, frame_height))
                    if scale < 1.0:
                        frame = cv2.resize(
                            frame,
                            (max(1, round(frame_width * scale)), max(1, round(frame_height * scale))),
                            interpolation=cv2.INTER_AREA,
                        )
                    encoded, buffer = cv2.imencode(".jpg", frame)
                    if encoded:
                        sampled_frames.append((frame_index, frame, buffer.tobytes()))
        capture.release()
        capture = None
        video_audio = _analyze_video_audio(temporary_path)
    finally:
        if capture is not None:
            capture.release()
        os.unlink(temporary_path)
    score = 20
    reasons = [f"Video container inspected at {width}x{height} with {frame_count} frames."]
    indicators = [{
        "name": "Video Frame Sampling",
        "observed_frames": frame_count,
        "sampled_frames": len(sampled_frames),
        "status": frame_sampling_status,
        "weight": 1,
    }]
    if frame_count == 0 or width == 0 or height == 0:
        score += 35
        reasons.append("Video stream metadata could not be decoded reliably.")
    elif frame_sampling_reason:
        score += 20
        reasons.append(frame_sampling_reason)
    try:
        face_detector = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
        if face_detector.empty():
            face_detector = None
    except (AttributeError, cv2.error):
        face_detector = None

    frame_results = []
    frame_scores = []
    face_counts = []
    for frame_index, frame, frame_bytes in sampled_frames:
        face_boxes = []
        if face_detector is not None:
            grayscale = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            face_boxes = list(face_detector.detectMultiScale(grayscale, scaleFactor=1.1, minNeighbors=4, minSize=(40, 40)))
        face_counts.append(len(face_boxes))
        inference_frame = frame_bytes
        if face_boxes:
            x, y, face_width, face_height = max(face_boxes, key=lambda box: box[2] * box[3])
            encoded, buffer = cv2.imencode(".jpg", frame[y:y + face_height, x:x + face_width])
            if encoded:
                inference_frame = buffer.tobytes()
        result = analyze_pretrained(inference_frame, "image")
        if result:
            frame_results.append(result)
            frame_scores.append({"frame_index": frame_index, "score": result["score"], "faces_detected": len(face_boxes)})

    if face_counts:
        indicators.append({"name": "Faces Detected in Sampled Frames", "count": sum(face_counts), "frames": len(face_counts)})
    if frame_results:
        pretrained_score = round(sum(result["score"] for result in frame_results) / len(frame_results))
        score = max(score, pretrained_score)
        reasons.append(f"Pretrained image detector analyzed {len(frame_results)} sampled video frame(s); mean model output was {pretrained_score}/99, not a calibrated probability.")
        indicators.append({"name": "Sampled Frame Deepfake Detector", "model_output": pretrained_score, "weight": max(1, pretrained_score), "frames": len(frame_results)})
    else:
        reasons.append("Pretrained image model unavailable; sampled frames were not deepfake-scored.")

    temporal_variance = statistics.pstdev([result["score"] for result in frame_results]) if len(frame_results) >= 2 else None
    if temporal_variance is not None and temporal_variance >= 20:
        variance_weight = min(20, round(temporal_variance / 2))
        score += variance_weight
        reasons.append(f"Deepfake scores vary across sampled frames (standard deviation {temporal_variance:.1f}); review the full clip for temporal inconsistency.")
        indicators.append({"name": "Temporal Deepfake Score Variance", "value": round(temporal_variance, 2), "weight": variance_weight, "frames": len(frame_results)})

    if video_audio["status"] == "analyzed":
        score = max(score, video_audio["score"])
        reasons.append(
            f"Audio from the first {VIDEO_AUDIO_MAX_SECONDS} seconds was analyzed with "
            f"{video_audio['method']} (risk score {video_audio['score']}/99; not a calibrated probability)."
        )
        indicators.append({
            "name": "Video Audio Deepfake Detector",
            "model_output": video_audio["score"],
            "weight": max(1, video_audio["score"]),
            "method": video_audio["method"],
        })
    else:
        reasons.append(video_audio["reason"])
        indicators.append({
            "name": "Video Audio Analysis",
            "status": video_audio["status"],
            "weight": 0,
        })

    return {
        "score": min(score, 99),
        "reasons": reasons,
        "indicators": indicators,
        "method": "pretrained-video-frame-detector" if frame_results else "video-frame-metadata",
        "pretrained_model": frame_results[0] if frame_results else None,
        "frame_scores": frame_scores,
        "face_counts": face_counts,
        "sampled_frame_count": len(sampled_frames),
        "sampling_limit": 30,
        "temporal_score_variance": round(temporal_variance, 2) if temporal_variance is not None else None,
        "audio_analysis": video_audio,
        "audio_video_synchronization": {
            "status": "not_analyzed",
            "reason": "Audio and video authenticity scores are inspected independently; lip-sync and temporal synchronization are not measured.",
        },
    }


def analyze_qr(content: bytes) -> dict[str, Any]:
    import cv2

    image = cv2.imdecode(np.frombuffer(content, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        return {"score": 20, "reasons": ["Image could not be decoded for QR inspection."], "indicators": [], "method": "qr-decoder"}
    decoded, points, _ = cv2.QRCodeDetector().detectAndDecode(image)
    if not decoded:
        return {"score": 5, "reasons": ["No QR payload was found in the uploaded image."], "indicators": [{"name": "QR Payload", "weight": 1, "status": "not_detected"}], "method": "qr-decoder"}
    risky = decoded.lower().startswith(("http://", "https://"))
    return {"score": 65 if risky else 35, "reasons": ["QR code decoded successfully; its payload was forwarded to URL analysis."], "indicators": [{"name": "QR Payload", "weight": 30 if risky else 10, "status": "url_payload" if risky else "non_url_payload"}], "decoded_payload": decoded, "method": "qr-decoder"}


def analyze_media(content: bytes, content_type: str, filename: str, category: str) -> dict[str, Any]:
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    try:
        if suffix in {"png", "jpg", "jpeg", "webp", "bmp", "tif", "tiff"}:
            qr_result = analyze_qr(content)
            if qr_result.get("decoded_payload"):
                return qr_result
        if content_type.startswith("image/") or suffix in {"png", "jpg", "jpeg", "webp", "bmp", "tif", "tiff"}:
            return analyze_image(content)
        if content_type.startswith("audio/") or suffix in AUDIO_SUFFIXES:
            return analyze_audio(content)
        if content_type.startswith("video/") or suffix in {"mp4", "avi", "mov"}:
            return analyze_video(content)
    except Exception as error:
        return {"score": 60, "reasons": [f"Media decoder reported an inspection error: {error}"], "indicators": [], "method": "media-fallback"}
    return {"score": 50, "reasons": [f"Media type {content_type or suffix or category} was hashed but has no specialized decoder installed."], "indicators": [], "method": "metadata-fallback"}
