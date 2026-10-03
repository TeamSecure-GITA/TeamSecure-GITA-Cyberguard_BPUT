import numpy as np
import cv2
import pytest
from types import SimpleNamespace

import deepfake_models
import media_engine


def test_video_analysis_localizes_faces_and_scores_temporal_variance(monkeypatch):
    frames = [
        np.full((64, 64, 3), value, dtype=np.uint8)
        for value in (20, 120, 240)
    ]

    class Capture:
        frame_index = 0

        def get(self, property_id):
            return {
                cv2.CAP_PROP_FRAME_COUNT: len(frames),
                cv2.CAP_PROP_FRAME_WIDTH: 64,
                cv2.CAP_PROP_FRAME_HEIGHT: 64,
            }[property_id]

        def set(self, property_id, value):
            self.frame_index = int(value)

        def read(self):
            return True, frames[self.frame_index].copy()

        def release(self):
            return None

    class FaceDetector:
        def empty(self):
            return False

        def detectMultiScale(self, grayscale, **kwargs):
            return [(8, 8, 40, 40)] if int(grayscale[0, 0]) < 50 else []

    scores = iter((5, 50, 95))
    monkeypatch.setattr(cv2, "VideoCapture", lambda _: Capture())
    monkeypatch.setattr(cv2, "CascadeClassifier", lambda _: FaceDetector(), raising=False)
    monkeypatch.setattr(deepfake_models, "analyze_pretrained", lambda *_: {"score": next(scores), "model": "test-model"})
    monkeypatch.setattr(media_engine, "_analyze_video_audio", lambda _: {
        "status": "analyzed",
        "score": 72,
        "method": "audio-test",
        "reasons": ["Audio detector test result."],
        "indicators": [],
        "max_seconds": 10,
    })

    result = media_engine.analyze_video(b"synthetic video bytes")

    assert len(result["frame_scores"]) == 3
    assert result["face_counts"] == [1, 0, 0]
    assert result["sampled_frame_count"] == 3
    assert result["temporal_score_variance"] >= 20
    assert result["score"] == 72
    assert result["audio_analysis"]["status"] == "analyzed"
    assert result["audio_video_synchronization"]["status"] == "not_analyzed"
    assert any(item["name"] == "Faces Detected in Sampled Frames" for item in result["indicators"])
    assert any(item["name"] == "Temporal Deepfake Score Variance" for item in result["indicators"])


def test_video_analysis_samples_a_bounded_spread_across_long_clips(monkeypatch):
    frame = np.full((64, 64, 3), 120, dtype=np.uint8)

    class Capture:
        frame_index = 0

        def get(self, property_id):
            return {
                cv2.CAP_PROP_FRAME_COUNT: 61,
                cv2.CAP_PROP_FRAME_WIDTH: 64,
                cv2.CAP_PROP_FRAME_HEIGHT: 64,
            }[property_id]

        def set(self, property_id, value):
            self.frame_index = int(value)

        def read(self):
            return True, frame.copy()

        def release(self):
            return None

    class FaceDetector:
        def empty(self):
            return False

        def detectMultiScale(self, grayscale, **kwargs):
            return []

    monkeypatch.setattr(cv2, "VideoCapture", lambda _: Capture())
    monkeypatch.setattr(cv2, "CascadeClassifier", lambda _: FaceDetector(), raising=False)
    monkeypatch.setattr(deepfake_models, "analyze_pretrained", lambda *_: {"score": 10, "model": "test-model"})
    monkeypatch.setattr(media_engine, "_analyze_video_audio", lambda _: {
        "status": "unavailable",
        "reason": "FFmpeg is not installed; the video's audio track was not analyzed.",
        "max_seconds": 10,
    })

    result = media_engine.analyze_video(b"synthetic long video bytes")

    assert result["sampled_frame_count"] == 30
    assert result["sampling_limit"] == 30
    assert len(result["frame_scores"]) == 30
    assert result["frame_scores"][0]["frame_index"] == 0
    assert result["frame_scores"][-1]["frame_index"] == 60


def test_video_analysis_downscales_sampled_frames_before_retaining_them(monkeypatch):
    frame = np.full((64, 96, 3), 120, dtype=np.uint8)
    analyzed_shapes = []

    class Capture:
        def get(self, property_id):
            return {
                cv2.CAP_PROP_FRAME_COUNT: 1,
                cv2.CAP_PROP_FRAME_WIDTH: 96,
                cv2.CAP_PROP_FRAME_HEIGHT: 64,
            }[property_id]

        def set(self, property_id, value):
            return None

        def read(self):
            return True, frame.copy()

        def release(self):
            return None

    class FaceDetector:
        def empty(self):
            return True

    def inspect_frame(content, modality):
        decoded = cv2.imdecode(np.frombuffer(content, dtype=np.uint8), cv2.IMREAD_COLOR)
        analyzed_shapes.append(decoded.shape[:2])
        return {"score": 10, "model": "test-model"}

    monkeypatch.setattr(media_engine, "VIDEO_FRAME_MAX_EDGE", 32)
    monkeypatch.setattr(cv2, "VideoCapture", lambda _: Capture())
    monkeypatch.setattr(cv2, "CascadeClassifier", lambda _: FaceDetector(), raising=False)
    monkeypatch.setattr(deepfake_models, "analyze_pretrained", inspect_frame)
    monkeypatch.setattr(media_engine, "_analyze_video_audio", lambda _: {
        "status": "unavailable",
        "reason": "Audio track not available.",
        "max_seconds": 10,
    })

    result = media_engine.analyze_video(b"synthetic video bytes")

    assert result["sampled_frame_count"] == 1
    assert analyzed_shapes == [(21, 32)]
    assert result["indicators"][0]["status"] == "analyzed"


def test_video_analysis_skips_sampling_for_oversized_frames_but_checks_audio(monkeypatch):
    audio_calls = []

    class Capture:
        def get(self, property_id):
            return {
                cv2.CAP_PROP_FRAME_COUNT: 30,
                cv2.CAP_PROP_FRAME_WIDTH: 4096,
                cv2.CAP_PROP_FRAME_HEIGHT: 4096,
            }[property_id]

        def set(self, property_id, value):
            raise AssertionError("oversized video frames must not be decoded")

        def read(self):
            raise AssertionError("oversized video frames must not be decoded")

        def release(self):
            return None

    class FaceDetector:
        def empty(self):
            return True

    monkeypatch.setattr(cv2, "VideoCapture", lambda _: Capture())
    monkeypatch.setattr(cv2, "CascadeClassifier", lambda _: FaceDetector(), raising=False)
    monkeypatch.setattr(deepfake_models, "analyze_pretrained", lambda *_: pytest.fail("no frame should be scored"))
    monkeypatch.setattr(media_engine, "_analyze_video_audio", lambda path: (
        audio_calls.append(path) or {
            "status": "unavailable",
            "reason": "FFmpeg is not installed.",
            "max_seconds": 10,
        }
    ))

    result = media_engine.analyze_video(b"synthetic large video bytes")

    assert result["sampled_frame_count"] == 0
    assert result["indicators"][0]["status"] == "skipped"
    assert "12,000,000-pixel" in result["reasons"][1]
    assert len(audio_calls) == 1


def test_video_audio_extraction_is_bounded_and_uses_existing_audio_detector(monkeypatch, tmp_path):
    captured = {}
    audio_result = {
        "score": 76,
        "method": "audio-test-model",
        "reasons": ["Audio anti-spoof detector flagged the segment."],
        "indicators": [{"name": "Audio detector", "weight": 76}],
        "pretrained_model": {"model": "test-audio-model"},
    }

    def fake_run(arguments, **kwargs):
        captured["arguments"] = arguments
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout=b"bounded-wav-data")

    monkeypatch.setattr(media_engine.shutil, "which", lambda _: "ffmpeg-test")
    monkeypatch.setattr(media_engine.subprocess, "run", fake_run)
    monkeypatch.setattr(media_engine, "analyze_audio", lambda content: audio_result if content == b"bounded-wav-data" else None)

    result = media_engine._analyze_video_audio(str(tmp_path / "clip.mp4"))

    assert result["status"] == "analyzed"
    assert result["score"] == 76
    assert result["max_seconds"] == 10
    assert captured["arguments"][0] == "ffmpeg-test"
    assert captured["arguments"][captured["arguments"].index("-t") + 1] == "10"
    assert captured["arguments"][-1] == "pipe:1"
    assert captured["kwargs"]["timeout"] == media_engine.VIDEO_AUDIO_TIMEOUT_SECONDS
    assert captured["kwargs"]["stderr"] == media_engine.subprocess.DEVNULL


def test_video_audio_extraction_reports_missing_ffmpeg_without_claiming_authenticity(monkeypatch, tmp_path):
    monkeypatch.setattr(media_engine.shutil, "which", lambda _: None)

    result = media_engine._analyze_video_audio(str(tmp_path / "clip.mp4"))

    assert result["status"] == "unavailable"
    assert "not analyzed" in result["reason"]
    assert "score" not in result


def test_video_audio_extraction_reports_timeout_and_decode_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(media_engine.shutil, "which", lambda _: "ffmpeg-test")

    def timeout(*args, **kwargs):
        raise media_engine.subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(media_engine.subprocess, "run", timeout)
    timed_out = media_engine._analyze_video_audio(str(tmp_path / "timeout.mp4"))
    assert timed_out["status"] == "timeout"

    monkeypatch.setattr(
        media_engine.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=b""),
    )
    decode_failed = media_engine._analyze_video_audio(str(tmp_path / "no-audio.mp4"))
    assert decode_failed["status"] == "failed"
    assert "may have no audio" in decode_failed["reason"]