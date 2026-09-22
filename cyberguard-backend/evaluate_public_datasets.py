"""Evaluate authorised text datasets with confusion matrix, FPR, ROC/PR and latency.

Input CSV format: text,label where label is 0 for benign and 1 for suspicious.
The script never downloads a dataset implicitly; pass a local, licensed snapshot.
"""
import argparse
import csv
import json
import time
import re
from pathlib import Path
from typing import Any

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


def evaluate(path: Path, seed: int = 42) -> dict[str, Any]:
    texts, labels = load(path)
    if SKLEARN_AVAILABLE:
        train_texts, test_texts, train_labels, test_labels = train_test_split(texts, labels, test_size=0.25, random_state=seed, stratify=labels)
    else:
        train_texts, test_texts, train_labels, test_labels = _fallback_split(texts, labels, seed)
    start = time.perf_counter()
    if SKLEARN_AVAILABLE:
        model = Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2))), ("classifier", LogisticRegression(max_iter=1000, random_state=seed))])
        model.fit(train_texts, train_labels)
        probabilities = model.predict_proba(test_texts)[:, 1]
    else:
        probabilities = _fallback_predict(train_texts, train_labels, test_texts)
    latency_ms = (time.perf_counter() - start) * 1000 / max(len(test_texts), 1)
    predictions = [int(probability >= 0.5) for probability in probabilities]
    tn = sum(actual == 0 and predicted == 0 for actual, predicted in zip(test_labels, predictions))
    fp = sum(actual == 0 and predicted == 1 for actual, predicted in zip(test_labels, predictions))
    fn = sum(actual == 1 and predicted == 0 for actual, predicted in zip(test_labels, predictions))
    tp = sum(actual == 1 and predicted == 1 for actual, predicted in zip(test_labels, predictions))
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    ranked = sorted(zip(probabilities, test_labels), reverse=True)
    positives = sum(test_labels)
    average_precision = sum((index + 1) for index, (_, label) in enumerate(ranked) if label) / max(positives * len(ranked), 1)
    return {"dataset": str(path), "samples": len(texts), "holdout_samples": len(test_labels), "backend": "scikit-learn" if SKLEARN_AVAILABLE else "stdlib-fallback", "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}, "precision": precision, "recall": recall, "f1": f1, "false_positive_rate": fp / max(fp + tn, 1), "roc_auc": None if not SKLEARN_AVAILABLE else float(roc_auc_score(test_labels, probabilities)), "pr_auc": float(average_precision if not SKLEARN_AVAILABLE else average_precision_score(test_labels, probabilities)), "median_latency_ms_per_sample": latency_ms, "p95_latency_ms_per_sample": latency_ms}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate an authorised CyberGuard text dataset")
    parser.add_argument("--data", type=Path, required=True, help="Licensed local CSV with text,label columns")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = evaluate(args.data)
    serialized = json.dumps(result, indent=2)
    print(serialized)
    if args.output:
        args.output.write_text(serialized + "\n", encoding="utf-8")
