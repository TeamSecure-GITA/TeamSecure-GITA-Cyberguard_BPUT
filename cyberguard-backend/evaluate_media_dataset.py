"""Evaluate labelled media folders.

Expected layout: dataset/{real,fake}/* with image/audio files. The command
records detector mode, confusion matrix and latency; it does not claim a model
is pretrained unless the API returns pretrained_model metadata.
"""
import argparse
import json
import math
import time
from pathlib import Path
from statistics import median
from typing import Mapping

from media_engine import analyze_media


NON_DEEPFAKE_METHODS = {"media-fallback", "metadata-fallback", "qr-decoder"}
IMAGE_SUFFIXES = {"bmp", "gif", "jpeg", "jpg", "png", "tif", "tiff", "webp"}
AUDIO_SUFFIXES = {"aac", "aif", "aiff", "flac", "m4a", "mp3", "oga", "ogg", "wav"}
VIDEO_SUFFIXES = {"avi", "m4v", "mkv", "mov", "mp4", "webm"}


def _validate_threshold(threshold: float) -> None:
    if not math.isfinite(threshold) or not 0 <= threshold <= 100:
        raise ValueError("Threshold must be between 0 and 100")


def _modality(path: Path) -> str:
    suffix = path.suffix.lower().lstrip(".")
    if suffix in IMAGE_SUFFIXES:
        return "image"
    if suffix in AUDIO_SUFFIXES:
        return "audio"
    if suffix in VIDEO_SUFFIXES:
        return "video"
    return "unknown"


def _group_by_modality(rows: list[dict], dataset_name: str) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(row["modality"], []).append(row)
    for modality, samples in groups.items():
        if {int(row["label"]) for row in samples} != {0, 1}:
            raise ValueError(f"{dataset_name} {modality} data must contain both real and fake samples.")
    return groups


def calculate_metrics(rows: list[dict], threshold: float | Mapping[str, float] = 50) -> dict:
    if isinstance(threshold, Mapping):
        for modality_threshold in threshold.values():
            _validate_threshold(modality_threshold)
        if any(row.get("modality") not in threshold for row in rows):
            raise ValueError("A calibrated threshold is required for every media modality.")
        thresholds = threshold
        reported_threshold = dict(threshold)
    else:
        _validate_threshold(threshold)
        thresholds = None
        reported_threshold = threshold
    if not rows:
        raise ValueError("Evaluation data must contain at least one sample.")
    labels = [int(row["label"]) for row in rows]
    if set(labels) != {0, 1}:
        raise ValueError("Evaluation data must contain both real and fake samples (labels 0 and 1)")
    raw_scores = [float(row["score"]) for row in rows]
    if any(not math.isfinite(score) for score in raw_scores):
        raise ValueError("Evaluation scores must be finite numbers")
    scores = [max(0.0, min(100.0, score)) for score in raw_scores]
    predictions = [
        int(score >= (thresholds[row["modality"]] if thresholds is not None else threshold))
        for score, row in zip(scores, rows)
    ]
    tn = sum(label == 0 and prediction == 0 for label, prediction in zip(labels, predictions))
    fp = sum(label == 0 and prediction == 1 for label, prediction in zip(labels, predictions))
    fn = sum(label == 1 and prediction == 0 for label, prediction in zip(labels, predictions))
    tp = sum(label == 1 and prediction == 1 for label, prediction in zip(labels, predictions))
    positives = tp + fn
    negatives = tn + fp
    precision = tp / max(tp + fp, 1)
    recall = tp / max(positives, 1)
    specificity = tn / max(negatives, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-12)

    groups: dict[float, list[int]] = {}
    for label, score in zip(labels, scores):
        bucket = groups.setdefault(score, [0, 0])
        bucket[0] += label
        bucket[1] += 1
    false_positive_before = 0
    concordant_pairs = 0.0
    average_precision = 0.0
    true_positive_seen = 0
    samples_seen = 0
    for score in sorted(groups):
        group_positives, group_size = groups[score]
        group_negatives = group_size - group_positives
        concordant_pairs += group_positives * false_positive_before + 0.5 * group_positives * group_negatives
        false_positive_before += group_negatives

    for score in sorted(groups, reverse=True):
        group_positives, group_size = groups[score]
        true_positive_seen += group_positives
        samples_seen += group_size
        average_precision += (group_positives / positives) * (true_positive_seen / samples_seen)

    return {
        "samples": len(rows),
        "threshold": reported_threshold,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "accuracy": (tp + tn) / len(rows),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": specificity,
        "false_positive_rate": fp / max(negatives, 1),
        "roc_auc": concordant_pairs / max(positives * negatives, 1),
        "pr_auc": average_precision,
        "score_semantics": "uncalibrated detector risk score; not a probability",
    }


def select_threshold(rows: list[dict], max_false_positive_rate: float = 0.05) -> dict:
    if not math.isfinite(max_false_positive_rate) or not 0 <= max_false_positive_rate <= 1:
        raise ValueError("Maximum false-positive rate must be between 0 and 1")
    candidate_thresholds = sorted({
        0.0,
        100.0,
        *(max(0.0, min(100.0, float(row["score"]))) for row in rows),
    })
    feasible = [
        calculate_metrics(rows, threshold)
        for threshold in candidate_thresholds
    ]
    feasible = [
        result for result in feasible
        if result["false_positive_rate"] <= max_false_positive_rate
    ]
    if not feasible:
        raise ValueError(
            "No threshold on the calibration data meets the requested false-positive rate; "
            "collect more representative calibration data or relax the target."
        )
    selected = max(
        feasible,
        key=lambda result: (
            result["recall"],
            result["precision"],
            result["threshold"],
        ),
    )
    return {
        "threshold": selected["threshold"],
        "target_false_positive_rate": max_false_positive_rate,
        "calibration_false_positive_rate": selected["false_positive_rate"],
        "calibration_recall": selected["recall"],
        "calibration_precision": selected["precision"],
        "calibration_samples": selected["samples"],
        "selection_method": "highest recall subject to the requested calibration false-positive-rate ceiling",
        "calibration_metrics": selected,
    }


def _score_dataset(root: Path) -> list[dict]:
    rows = []
    for label_name, label in (("real", 0), ("fake", 1)):
        class_directory = root / label_name
        if not class_directory.is_dir():
            raise ValueError(f"Dataset is missing required directory: {class_directory}")
        files = sorted(path for path in class_directory.rglob("*") if path.is_file())
        if not files:
            raise ValueError(f"Dataset class directory contains no files: {class_directory}")
        for path in files:
            content = path.read_bytes()
            started = time.perf_counter()
            result = analyze_media(content, "", path.name, "deepfake")
            elapsed = (time.perf_counter() - started) * 1000
            method = result.get("method")
            if method in NON_DEEPFAKE_METHODS:
                raise ValueError(
                    f"Deepfake evaluation failed for {path}: {': '.join(result.get('reasons', ['no deepfake detector available']))}"
                )
            if not isinstance(result.get("score"), (int, float)) or not math.isfinite(float(result["score"])):
                raise ValueError(f"Media detector returned no finite numeric score for {path}")
            rows.append({
                "label": label,
                "modality": _modality(path),
                "score": result["score"],
                "latency_ms": elapsed,
                "method": method,
                "pretrained": bool(result.get("pretrained_model")),
            })
    return rows


def evaluate(
    root: Path,
    threshold: float = 50,
    calibration_root: Path | None = None,
    max_false_positive_rate: float = 0.05,
) -> dict:
    if calibration_root is not None and root.resolve() == calibration_root.resolve():
        raise ValueError("Calibration and final evaluation datasets must be separate directories")
    test_rows = _score_dataset(root)
    test_groups = _group_by_modality(test_rows, "Final evaluation")
    selected_threshold: float | dict[str, float] = threshold
    calibration_by_modality = None
    if calibration_root is not None:
        calibration_rows = _score_dataset(calibration_root)
        calibration_groups = _group_by_modality(calibration_rows, "Calibration")
        if set(calibration_groups) != set(test_groups):
            raise ValueError("Calibration and final evaluation datasets must contain the same media modalities.")
        calibration_by_modality = {
            modality: select_threshold(rows, max_false_positive_rate)
            for modality, rows in calibration_groups.items()
        }
        thresholds_by_modality = {
            modality: result["threshold"]
            for modality, result in calibration_by_modality.items()
        }
        selected_threshold = (
            next(iter(thresholds_by_modality.values()))
            if len(thresholds_by_modality) == 1
            else thresholds_by_modality
        )

    per_modality = {}
    for modality, rows in test_groups.items():
        modality_threshold = (
            selected_threshold[modality]
            if isinstance(selected_threshold, Mapping)
            else selected_threshold
        )
        per_modality[modality] = {
            **calculate_metrics(rows, modality_threshold),
            "median_latency_ms": median(row["latency_ms"] for row in rows),
            "p95_latency_ms": sorted(row["latency_ms"] for row in rows)[
                max(0, math.ceil(len(rows) * 0.95) - 1)
            ],
            "methods": sorted({row["method"] for row in rows}),
            "pretrained_outputs": sum(row["pretrained"] for row in rows),
            "threshold_selection": (
                calibration_by_modality[modality]
                if calibration_by_modality
                else None
            ),
        }

    result = calculate_metrics(test_rows, selected_threshold)
    result.update({
        "dataset": str(root),
        "threshold_source": "separate_calibration_dataset" if calibration_by_modality else "fixed_cutoff",
        "threshold_selection": (
            next(iter(calibration_by_modality.values()))
            if calibration_by_modality and len(calibration_by_modality) == 1
            else calibration_by_modality
        ),
        "score_interpretation": "Detector risk scores and selected decision threshold are not probabilities or proof of authenticity.",
        "median_latency_ms": median(row["latency_ms"] for row in test_rows),
        "p95_latency_ms": sorted(row["latency_ms"] for row in test_rows)[max(0, math.ceil(len(test_rows) * 0.95) - 1)],
        "methods": sorted({row["method"] for row in test_rows}),
        "pretrained_outputs": sum(row["pretrained"] for row in test_rows),
        "modalities": sorted(test_groups),
        "per_modality": per_modality,
    })
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate CyberGuard media detectors")
    parser.add_argument("--data", type=Path, required=True, help="Untouched final dataset with real/ and fake/ directories")
    parser.add_argument("--threshold", type=float, default=50, help="Fixed risk-score cutoff from 0 to 100; ignored when --calibration-data is supplied")
    parser.add_argument("--calibration-data", type=Path, help="Separate authorised calibration dataset with real/ and fake/ directories")
    parser.add_argument("--max-false-positive-rate", type=float, default=0.05, help="Calibration false-positive-rate ceiling between 0 and 1")
    parser.add_argument("--output", type=Path, help="Optional JSON output path")
    args = parser.parse_args()
    result = evaluate(
        args.data,
        args.threshold,
        args.calibration_data,
        args.max_false_positive_rate,
    )
    serialized = json.dumps(result, indent=2)
    print(serialized)
    if args.output:
        args.output.write_text(serialized + "\n", encoding="utf-8")
