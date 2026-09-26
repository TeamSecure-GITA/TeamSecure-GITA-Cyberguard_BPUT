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

from media_engine import analyze_media


def calculate_metrics(rows: list[dict], threshold: float = 50) -> dict:
    if not 0 <= threshold <= 100:
        raise ValueError("Threshold must be between 0 and 100")
    labels = [int(row["label"]) for row in rows]
    if set(labels) != {0, 1}:
        raise ValueError("Evaluation data must contain both real and fake samples (labels 0 and 1)")
    scores = [max(0.0, min(100.0, float(row["score"]))) for row in rows]
    predictions = [int(score >= threshold) for score in scores]
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
        "threshold": threshold,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "accuracy": (tp + tn) / len(rows),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "specificity": specificity,
        "false_positive_rate": fp / max(negatives, 1),
        "roc_auc": concordant_pairs / max(positives * negatives, 1),
        "pr_auc": average_precision,
    }


def evaluate(root: Path, threshold: float = 50) -> dict:
    rows = []
    for label_name, label in (("real", 0), ("fake", 1)):
        for path in (root / label_name).rglob("*"):
            if not path.is_file():
                continue
            content = path.read_bytes()
            started = time.perf_counter()
            result = analyze_media(content, "", path.name, "deepfake")
            elapsed = (time.perf_counter() - started) * 1000
            rows.append({"label": label, "score": result["score"], "latency_ms": elapsed, "method": result.get("method"), "pretrained": bool(result.get("pretrained_model"))})
    if not rows:
        raise ValueError("Dataset must contain real/ and fake/ directories with media files")
    result = calculate_metrics(rows, threshold)
    result.update({
        "median_latency_ms": median(row["latency_ms"] for row in rows),
        "p95_latency_ms": sorted(row["latency_ms"] for row in rows)[max(0, math.ceil(len(rows) * 0.95) - 1)],
        "methods": sorted({row["method"] for row in rows}),
        "pretrained_outputs": sum(row["pretrained"] for row in rows),
    })
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate CyberGuard media detectors")
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--threshold", type=float, default=50, help="Risk-score cutoff from 0 to 100")
    args = parser.parse_args()
    print(json.dumps(evaluate(args.data, args.threshold), indent=2))
