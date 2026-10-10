"""Evaluate authorised text datasets with confusion matrix, FPR, ROC/PR and latency.

Input CSV format: text,label where label is 0 for benign and 1 for suspicious.
The script never downloads a dataset implicitly; pass a local, licensed snapshot.
"""
import argparse
import csv
import hashlib
import json
import math
import time
import re
from pathlib import Path
from statistics import median
from typing import Any
from calibration_metrics import probability_calibration

try:
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]{2,}", text.lower()))


def _fallback_predict(train_texts, train_labels, test_texts):
    positive = set().union(*[_tokens(text) for text, label in zip(train_texts, train_labels) if label == 1])
    negative = set().union(*[_tokens(text) for text, label in zip(train_texts, train_labels) if label == 0])
    scores = []
    for text in test_texts:
        words = _tokens(text)
        suspicious = len(words & positive) / max(len(words), 1)
        benign = len(words & negative) / max(len(words), 1)
        scores.append(max(0.001, min(0.999, 0.5 + (suspicious - benign))))
    return scores


def _fallback_split(texts, labels, seed: int):
    indexes = list(range(len(texts)))
    positives = [index for index in indexes if labels[index] == 1]
    negatives = [index for index in indexes if labels[index] == 0]
    positives = positives[seed % max(len(positives), 1):] + positives[:seed % max(len(positives), 1)]
    negatives = negatives[seed % max(len(negatives), 1):] + negatives[:seed % max(len(negatives), 1)]
    holdout_size = max(1, round(len(texts) * 0.25))
    holdout = (positives[:holdout_size // 2] + negatives[:holdout_size - holdout_size // 2])[:holdout_size]
    training = [index for index in indexes if index not in holdout]
    return ([texts[index] for index in training], [texts[index] for index in holdout], [labels[index] for index in training], [labels[index] for index in holdout])


def load(path: Path):
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    texts = [row["text"].strip() for row in rows if row.get("text", "").strip()]
    labels = [int(row["label"]) for row in rows if row.get("text", "").strip()]
    if len(set(labels)) != 2:
        raise ValueError("Dataset must contain both label 0 and label 1")
    return texts, labels


def evaluate(path: Path, seed: int = 42, threshold: float = 50) -> dict[str, Any]:
    if not 0 <= threshold <= 100:
        raise ValueError("Threshold must be between 0 and 100")
    texts, labels = load(path)
    if SKLEARN_AVAILABLE:
        train_texts, test_texts, train_labels, test_labels = train_test_split(texts, labels, test_size=0.25, random_state=seed, stratify=labels)
    else:
        train_texts, test_texts, train_labels, test_labels = _fallback_split(texts, labels, seed)
    fit_started = time.perf_counter()
    if SKLEARN_AVAILABLE:
        model = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2))), ("classifier", LogisticRegression(max_iter=1000, random_state=seed))])
        model.fit(train_texts, train_labels)
    fit_time_ms = (time.perf_counter() - fit_started) * 1000
    probabilities = []
    sample_latencies = []
    for text in test_texts:
        inference_started = time.perf_counter()
        if SKLEARN_AVAILABLE:
            probability = float(model.predict_proba([text])[0][1])
        else:
            probability = float(_fallback_predict(train_texts, train_labels, [text])[0])
        sample_latencies.append((time.perf_counter() - inference_started) * 1000)
        probabilities.append(probability)
    predictions = [int(probability >= threshold / 100) for probability in probabilities]
    tn = sum(actual == 0 and predicted == 0 for actual, predicted in zip(test_labels, predictions))
    fp = sum(actual == 0 and predicted == 1 for actual, predicted in zip(test_labels, predictions))
    fn = sum(actual == 1 and predicted == 0 for actual, predicted in zip(test_labels, predictions))
    tp = sum(actual == 1 and predicted == 1 for actual, predicted in zip(test_labels, predictions))
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    positives = sum(test_labels)
    ranked = sorted(zip(probabilities, test_labels), reverse=True)
    average_precision = sum((index + 1) for index, (_, label) in enumerate(ranked) if label) / max(positives * len(ranked), 1)
    sorted_latencies = sorted(sample_latencies)
    calibration = probability_calibration(test_labels, probabilities)
    return {"dataset": str(path), "samples": len(texts), "holdout_samples": len(test_labels), "backend": "scikit-learn" if SKLEARN_AVAILABLE else "stdlib-fallback", "decision_threshold": threshold, "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}, "precision": precision, "recall": recall, "f1": f1, "false_positive_rate": fp / max(fp + tn, 1), "roc_auc": None if not SKLEARN_AVAILABLE else float(roc_auc_score(test_labels, probabilities)), "pr_auc": float(average_precision if not SKLEARN_AVAILABLE else average_precision_score(test_labels, probabilities)), "calibration": calibration, "fit_time_ms": fit_time_ms, "median_latency_ms_per_sample": median(sample_latencies), "p95_latency_ms_per_sample": sorted_latencies[max(0, math.ceil(len(sorted_latencies) * 0.95) - 1)]}


def _load_fixed_split(path: Path, expected_split: str) -> list[dict[str, str | int]]:
    required = {"text", "label", "category", "source", "license", "split"}
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(
                "Fixed-split evaluation requires text,label,category,source,license,split columns."
            )
        rows = list(reader)

    cleaned = []
    for line_number, row in enumerate(rows, start=2):
        text = (row.get("text") or "").strip()
        category = (row.get("category") or "").strip().casefold()
        source = (row.get("source") or "").strip()
        license_name = (row.get("license") or "").strip()
        split = (row.get("split") or "").strip().casefold()
        try:
            label = int(row.get("label", ""))
        except (TypeError, ValueError) as error:
            raise ValueError(f"{path}:{line_number} has an invalid binary label.") from error
        if not text or not category or not source or not license_name:
            raise ValueError(f"{path}:{line_number} is missing text, category, source, or license provenance.")
        if label not in {0, 1}:
            raise ValueError(f"{path}:{line_number} label must be 0 or 1.")
        if split != expected_split:
            raise ValueError(f"{path}:{line_number} must be marked split={expected_split}.")
        cleaned.append({
            "text": text,
            "label": label,
            "category": category,
            "source": source,
            "license": license_name,
            "split": split,
        })
    if not cleaned:
        raise ValueError(f"{expected_split.capitalize()} evaluation split is empty: {path}")
    return cleaned


def _text_fingerprint(text: str) -> str:
    normalized = " ".join(text.casefold().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _select_probability_threshold(labels: list[int], probabilities: list[float], max_false_positive_rate: float) -> dict[str, float | str]:
    if not math.isfinite(max_false_positive_rate) or not 0 <= max_false_positive_rate <= 1:
        raise ValueError("Maximum false-positive rate must be between 0 and 1.")
    if set(labels) != {0, 1}:
        raise ValueError("Each calibration category must contain benign and suspicious examples.")
    candidates = sorted({0.0, 1.0, *probabilities})
    feasible = []
    negatives = sum(label == 0 for label in labels)
    for threshold in candidates:
        predictions = [int(score >= threshold) for score in probabilities]
        false_positives = sum(label == 0 and prediction == 1 for label, prediction in zip(labels, predictions))
        true_positives = sum(label == 1 and prediction == 1 for label, prediction in zip(labels, predictions))
        false_negatives = sum(label == 1 and prediction == 0 for label, prediction in zip(labels, predictions))
        false_positive_rate = false_positives / max(negatives, 1)
        if false_positive_rate <= max_false_positive_rate:
            recall = true_positives / max(true_positives + false_negatives, 1)
            feasible.append((recall, threshold, false_positive_rate))
    if not feasible:
        raise ValueError("No threshold on calibration data meets the requested false-positive-rate ceiling.")
    recall, threshold, false_positive_rate = max(feasible, key=lambda item: (item[0], item[1]))
    return {
        "threshold": threshold,
        "calibration_false_positive_rate": false_positive_rate,
        "calibration_recall": recall,
        "selection_method": "highest calibration recall under the requested false-positive-rate ceiling",
    }


def evaluate_fixed_splits(
    training_path: Path,
    calibration_path: Path,
    test_path: Path,
    max_false_positive_rate: float = 0.05,
) -> dict[str, Any]:
    """Train, choose thresholds, and report metrics on three disjoint manifested datasets."""
    if len({path.resolve() for path in (training_path, calibration_path, test_path)}) != 3:
        raise ValueError("Training, calibration, and untouched test datasets must be separate files.")
    training = _load_fixed_split(training_path, "train")
    calibration = _load_fixed_split(calibration_path, "calibration")
    test = _load_fixed_split(test_path, "test")

    fingerprints: dict[str, str] = {}
    for split_name, rows in (("train", training), ("calibration", calibration), ("test", test)):
        for row in rows:
            fingerprint = _text_fingerprint(row["text"])
            previous_split = fingerprints.get(fingerprint)
            if previous_split:
                raise ValueError(f"Duplicate normalized text occurs in both {previous_split} and {split_name} splits.")
            fingerprints[fingerprint] = split_name

    groups = {
        split_name: {
            category: [row for row in rows if row["category"] == category]
            for category in sorted({row["category"] for row in rows})
        }
        for split_name, rows in (("train", training), ("calibration", calibration), ("test", test))
    }
    categories = set(groups["train"])
    if not categories or set(groups["calibration"]) != categories or set(groups["test"]) != categories:
        raise ValueError("Train, calibration, and test splits must contain the same non-empty categories.")

    reports = {}
    for category in sorted(categories):
        split_rows = {name: values[category] for name, values in groups.items()}
        for split_name, rows in split_rows.items():
            if {int(row["label"]) for row in rows} != {0, 1}:
                raise ValueError(f"Category {category} in {split_name} must contain benign and suspicious examples.")
        train_texts = [str(row["text"]) for row in split_rows["train"]]
        train_labels = [int(row["label"]) for row in split_rows["train"]]
        calibration_texts = [str(row["text"]) for row in split_rows["calibration"]]
        calibration_labels = [int(row["label"]) for row in split_rows["calibration"]]
        test_texts = [str(row["text"]) for row in split_rows["test"]]
        test_labels = [int(row["label"]) for row in split_rows["test"]]

        fit_started = time.perf_counter()
        if SKLEARN_AVAILABLE:
            model = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2))), ("classifier", LogisticRegression(max_iter=1000, random_state=42))])
            model.fit(train_texts, train_labels)
            predict = lambda texts: [float(value) for value in model.predict_proba(texts)[:, 1]]
            backend = "scikit-learn"
        else:
            predict = lambda texts: _fallback_predict(train_texts, train_labels, texts)
            backend = "stdlib-fallback"
        fit_time_ms = (time.perf_counter() - fit_started) * 1000

        calibration_latencies = []
        calibration_probabilities = []
        for text in calibration_texts:
            started = time.perf_counter()
            calibration_probabilities.extend(predict([text]))
            calibration_latencies.append((time.perf_counter() - started) * 1000)
        threshold_policy = _select_probability_threshold(
            calibration_labels,
            calibration_probabilities,
            max_false_positive_rate,
        )

        sample_latencies = []
        probabilities = []
        for text in test_texts:
            started = time.perf_counter()
            probabilities.extend(predict([text]))
            sample_latencies.append((time.perf_counter() - started) * 1000)
        predictions = [int(probability >= threshold_policy["threshold"]) for probability in probabilities]
        tn = sum(actual == 0 and predicted == 0 for actual, predicted in zip(test_labels, predictions))
        fp = sum(actual == 0 and predicted == 1 for actual, predicted in zip(test_labels, predictions))
        fn = sum(actual == 1 and predicted == 0 for actual, predicted in zip(test_labels, predictions))
        tp = sum(actual == 1 and predicted == 1 for actual, predicted in zip(test_labels, predictions))
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        sorted_latencies = sorted(sample_latencies)
        reports[category] = {
            "training_samples": len(train_texts),
            "calibration_samples": len(calibration_texts),
            "untouched_test_samples": len(test_texts),
            "threshold_policy": threshold_policy,
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
            "precision": precision,
            "recall": recall,
            "f1": 2 * precision * recall / max(precision + recall, 1e-12),
            "false_positive_rate": fp / max(tn + fp, 1),
            "roc_auc": None if not SKLEARN_AVAILABLE else float(roc_auc_score(test_labels, probabilities)),
            "pr_auc": float(average_precision_score(test_labels, probabilities)) if SKLEARN_AVAILABLE else None,
            "probability_calibration": probability_calibration(test_labels, probabilities),
            "fit_time_ms": fit_time_ms,
            "median_latency_ms_per_sample": median(sample_latencies),
            "p95_latency_ms_per_sample": sorted_latencies[max(0, math.ceil(len(sorted_latencies) * 0.95) - 1)],
            "backend": backend,
        }

    provenance = {
        split_name: sorted({f"{row['source']} ({row['license']})" for row in rows})
        for split_name, rows in (("train", training), ("calibration", calibration), ("test", test))
    }
    return {
        "method": "separate train/calibration/untouched test files; exact normalized duplicates rejected across splits",
        "category_reports": reports,
        "provenance": provenance,
        "license_validation": "Source and license labels are recorded from the manifests; redistribution and consent terms still require human verification.",
        "test_split_reused_for_training_or_threshold_selection": False,
        "threshold_selection_uses_test_data": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate an authorised CyberGuard text dataset")
    data_group = parser.add_mutually_exclusive_group(required=True)
    data_group.add_argument("--data", type=Path, help="Quick seeded holdout CSV with text,label columns")
    data_group.add_argument("--train-data", type=Path, help="Fixed-split train CSV with text,label,category,source,license,split columns")
    parser.add_argument("--calibration-data", type=Path, help="Separate category-specific calibration split CSV")
    parser.add_argument("--test-data", type=Path, help="Untouched category-specific final test split CSV")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--threshold", type=float, default=50, help="Suspicious-class probability cutoff from 0 to 100")
    args = parser.parse_args()
    if args.data:
        if args.calibration_data or args.test_data:
            parser.error("--data cannot be combined with fixed-split arguments")
        result = evaluate(args.data, threshold=args.threshold)
    else:
        if not args.calibration_data or not args.test_data:
            parser.error("--train-data requires both --calibration-data and --test-data")
        result = evaluate_fixed_splits(args.train_data, args.calibration_data, args.test_data)
    serialized = json.dumps(result, indent=2)
    print(serialized)
    if args.output:
        args.output.write_text(serialized + "\n", encoding="utf-8")
