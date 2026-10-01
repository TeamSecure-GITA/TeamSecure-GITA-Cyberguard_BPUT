import numpy as np
import cv2

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

    result = media_engine.analyze_video(b"synthetic video bytes")

    assert len(result["frame_scores"]) == 3
    assert result["face_counts"] == [1, 0, 0]
    assert result["temporal_score_variance"] >= 20
    assert any(item["name"] == "Faces Detected in Sampled Frames" for item in result["indicators"])
    assert any(item["name"] == "Temporal Deepfake Score Variance" for item in result["indicators"])