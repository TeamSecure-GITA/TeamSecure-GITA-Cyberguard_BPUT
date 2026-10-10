import csv

import pytest

import evaluate_public_datasets


def _write_split(path, split, records):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["text", "label", "category", "source", "license", "split"])
        writer.writeheader()
        for text, label, category in records:
            writer.writerow({
                "text": text,
                "label": label,
                "category": category,
                "source": "test-corpus-v1",
                "license": "CC-BY-4.0",
                "split": split,
            })


def test_fixed_text_splits_report_metrics_per_category_without_test_leakage(tmp_path):
    pytest.importorskip("sklearn")
    train = tmp_path / "train.csv"
    calibration = tmp_path / "calibration.csv"
    test = tmp_path / "test.csv"
    _write_split(train, "train", [
        ("routine campus email about library hours", 0, "email"),
        ("urgent account password reset payment now", 1, "email"),
        ("official university event schedule", 0, "url"),
        ("verify wallet credentials at suspicious link", 1, "url"),
    ])
    _write_split(calibration, "calibration", [
        ("normal faculty meeting reminder", 0, "email"),
        ("confirm your password immediately", 1, "email"),
        ("public course catalog page", 0, "url"),
        ("login verify account now", 1, "url"),
    ])
    _write_split(test, "test", [
        ("benign campus examination notice", 0, "email"),
        ("reset your bank password now", 1, "email"),
        ("official department contact page", 0, "url"),
        ("verify your account using this link", 1, "url"),
    ])

    result = evaluate_public_datasets.evaluate_fixed_splits(train, calibration, test)

    assert set(result["category_reports"]) == {"email", "url"}
    assert result["test_split_reused_for_training_or_threshold_selection"] is False
    assert result["threshold_selection_uses_test_data"] is False
    for report in result["category_reports"].values():
        assert report["untouched_test_samples"] == 2
        assert report["threshold_policy"]["selection_method"].startswith("highest calibration recall")
        assert report["p95_latency_ms_per_sample"] >= 0
        assert "false_positive_rate" in report
        assert "probability_calibration" in report


def test_fixed_text_splits_reject_normalized_duplicate_leakage(tmp_path):
    train = tmp_path / "train.csv"
    calibration = tmp_path / "calibration.csv"
    test = tmp_path / "test.csv"
    _write_split(train, "train", [
        ("Routine account notice", 0, "email"),
        ("Urgent password theft", 1, "email"),
    ])
    _write_split(calibration, "calibration", [
        ("Normal meeting update", 0, "email"),
        ("Confirm bank password", 1, "email"),
    ])
    _write_split(test, "test", [
        (" routine   ACCOUNT NOTICE ", 0, "email"),
        ("A distinct malicious example", 1, "email"),
    ])

    with pytest.raises(ValueError, match="Duplicate normalized text"):
        evaluate_public_datasets.evaluate_fixed_splits(train, calibration, test)
