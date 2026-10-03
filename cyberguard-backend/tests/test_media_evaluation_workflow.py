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
    assert result["calibration"]["calibration_false_positive_rate"] == 0
    assert result["calibration"]["calibration_recall"] == 1
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
