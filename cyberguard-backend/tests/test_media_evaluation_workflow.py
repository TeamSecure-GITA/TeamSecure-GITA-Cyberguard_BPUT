import pytest

import evaluate_media_dataset


def _write_media_dataset(root, samples):
    for label, name, score in samples:
        directory = root / ("real" if label == 0 else "fake")
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_bytes(str(score).encode("ascii"))


def test_threshold_selection_uses_only_separate_calibration_data(tmp_path, monkeypatch):
    calibration = tmp_path / "calibration"
    final = tmp_path / "final"
    _write_media_dataset(calibration, [
        (0, "real-low.bin", 10),
        (0, "real-high.bin", 45),
        (1, "fake-low.bin", 60),
        (1, "fake-high.bin", 90),
    ])
    _write_media_dataset(final, [
        (0, "real.bin", 20),
        (1, "fake.bin", 70),
    ])

    monkeypatch.setattr(evaluate_media_dataset, "analyze_media", lambda content, *_: {
        "score": int(content.decode("ascii")),
        "method": "test-media-detector",
    })

    result = evaluate_media_dataset.evaluate(
        final,
        calibration_root=calibration,
        max_false_positive_rate=0,
    )

    assert result["threshold"] == 60
    assert result["threshold_source"] == "separate_calibration_dataset"
    assert result["confusion_matrix"] == {"tn": 1, "fp": 0, "fn": 0, "tp": 1}
    assert result["threshold_selection"]["calibration_false_positive_rate"] == 0
    assert result["threshold_selection"]["calibration_recall"] == 1
    assert result["samples"] == 2
    assert "not probabilities" in result["score_interpretation"]


def test_threshold_selection_rejects_invalid_target_or_infeasible_target():
    rows = [
        {"label": 0, "score": 100},
        {"label": 1, "score": 90},
    ]

    with pytest.raises(ValueError, match="between 0 and 1"):
        evaluate_media_dataset.select_threshold(rows, 1.1)
    with pytest.raises(ValueError, match="No threshold"):
        evaluate_media_dataset.select_threshold(rows, 0)


def test_final_and_calibration_directories_must_be_distinct(tmp_path):
    _write_media_dataset(tmp_path, [
        (0, "real.bin", 10),
        (1, "fake.bin", 90),
    ])

    with pytest.raises(ValueError, match="separate directories"):
        evaluate_media_dataset.evaluate(tmp_path, calibration_root=tmp_path)


def test_media_evaluation_fails_explicitly_on_unsupported_media(tmp_path, monkeypatch):
    _write_media_dataset(tmp_path, [
        (0, "real.bin", 10),
        (1, "fake.bin", 90),
    ])
    monkeypatch.setattr(evaluate_media_dataset, "analyze_media", lambda *_: {
        "score": 50,
        "method": "metadata-fallback",
        "reasons": ["no supported decoder"],
    })

    with pytest.raises(ValueError, match="no supported decoder"):
        evaluate_media_dataset.evaluate(tmp_path)


def test_deepfake_evaluation_does_not_count_qr_detection_as_deepfake_model(tmp_path, monkeypatch):
    _write_media_dataset(tmp_path, [
        (0, "real.bin", 10),
        (1, "fake.bin", 90),
    ])
    monkeypatch.setattr(evaluate_media_dataset, "analyze_media", lambda *_: {
        "score": 50,
        "method": "qr-decoder",
        "reasons": ["QR payload found"],
    })

    with pytest.raises(ValueError, match="QR payload found"):
        evaluate_media_dataset.evaluate(tmp_path)


def test_media_metrics_reject_nonfinite_scores():
    with pytest.raises(ValueError, match="finite numbers"):
        evaluate_media_dataset.calculate_metrics([
            {"label": 0, "score": float("nan")},
            {"label": 1, "score": 90},
        ])


def test_image_and_audio_calibration_are_selected_and_reported_separately(tmp_path, monkeypatch):
    calibration = tmp_path / "calibration"
    final = tmp_path / "final"
    _write_media_dataset(calibration, [
        (0, "real-low.jpg", 10),
        (0, "real-high.jpg", 40),
        (1, "fake-low.jpg", 60),
        (1, "fake-high.jpg", 90),
        (0, "real-low.wav", 10),
        (0, "real-high.wav", 80),
        (1, "fake-low.wav", 90),
        (1, "fake-high.wav", 95),
        (0, "real-low.mp4", 15),
        (0, "real-high.mp4", 45),
        (1, "fake-low.mp4", 70),
        (1, "fake-high.mp4", 85),
    ])
    _write_media_dataset(final, [
        (0, "real.jpg", 20),
        (1, "fake.jpg", 70),
        (0, "real.wav", 30),
        (1, "fake.wav", 92),
        (0, "real.mp4", 25),
        (1, "fake.mp4", 75),
    ])
    monkeypatch.setattr(evaluate_media_dataset, "analyze_media", lambda content, *_: {
        "score": int(content.decode("ascii")),
        "method": "test-media-detector",
    })

    result = evaluate_media_dataset.evaluate(
        final,
        calibration_root=calibration,
        max_false_positive_rate=0,
    )

    assert result["threshold"] == {"audio": 90, "image": 60, "video": 70}
    assert result["modalities"] == ["audio", "image", "video"]
    assert result["confusion_matrix"] == {"tn": 3, "fp": 0, "fn": 0, "tp": 3}
    assert result["per_modality"]["image"]["threshold"] == 60
    assert result["per_modality"]["audio"]["threshold"] == 90
    assert result["per_modality"]["video"]["threshold"] == 70
    assert result["per_modality"]["image"]["threshold_selection"]["calibration_recall"] == 1
    assert result["per_modality"]["image"]["confusion_matrix"] == {"tn": 1, "fp": 0, "fn": 0, "tp": 1}
    assert result["per_modality"]["audio"]["confusion_matrix"] == {"tn": 1, "fp": 0, "fn": 0, "tp": 1}
    assert result["per_modality"]["video"]["confusion_matrix"] == {"tn": 1, "fp": 0, "fn": 0, "tp": 1}


def test_each_modality_requires_both_labels_for_calibration_and_final_sets(tmp_path, monkeypatch):
    final = tmp_path / "final"
    calibration = tmp_path / "calibration"
    _write_media_dataset(final, [
        (0, "real.jpg", 10),
        (1, "fake.jpg", 90),
        (0, "real.wav", 20),
    ])
    _write_media_dataset(calibration, [
        (0, "real.jpg", 10),
        (1, "fake.jpg", 90),
        (0, "real.wav", 20),
        (1, "fake.wav", 80),
    ])
    monkeypatch.setattr(evaluate_media_dataset, "analyze_media", lambda content, *_: {
        "score": int(content.decode("ascii")),
        "method": "test-media-detector",
    })

    with pytest.raises(ValueError, match="Final evaluation audio data must contain both real and fake"):
        evaluate_media_dataset.evaluate(final, calibration_root=calibration)


def test_calibration_and_test_sets_must_cover_the_same_modalities(tmp_path, monkeypatch):
    final = tmp_path / "final"
    calibration = tmp_path / "calibration"
    _write_media_dataset(final, [
        (0, "real.jpg", 10),
        (1, "fake.jpg", 90),
        (0, "real.wav", 20),
        (1, "fake.wav", 80),
    ])
    _write_media_dataset(calibration, [
        (0, "real.jpg", 10),
        (1, "fake.jpg", 90),
    ])
    monkeypatch.setattr(evaluate_media_dataset, "analyze_media", lambda content, *_: {
        "score": int(content.decode("ascii")),
        "method": "test-media-detector",
    })

    with pytest.raises(ValueError, match="same media modalities"):
        evaluate_media_dataset.evaluate(final, calibration_root=calibration)
