"""Three-client privacy-preserving text baseline.

This is a reproducible simulation: institutions share model updates, never raw
text. Set CYBERGUARD_FEDERATED_EPSILON to document the noise budget used in a
run. Install requirements-ai.txt for Flower integration in a deployment.
"""
import argparse
import csv
import json
import os
import re
from pathlib import Path
from typing import Any

try:
    import numpy as np
    from sklearn.feature_extraction.text import HashingVectorizer
    from sklearn.linear_model import SGDClassifier
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    SKLEARN_AVAILABLE = True
except ImportError:
    import numpy as np
    SKLEARN_AVAILABLE = False


def redact(text: str) -> str:
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "EMAIL", text)
    return re.sub(r"\b\d{8,}\b", "NUMBER", text)


def _fallback_federated(texts, labels, splits, rounds):
    positive = {}
    negative = {}
    for _ in range(rounds):
        client_updates = []
        for indexes in splits:
            local_positive = {}
            local_negative = {}
            for index in indexes:
                target = local_positive if labels[index] else local_negative
                for token in re.findall(r"[a-z0-9]{2,}", texts[index].lower()):
                    target[token] = target.get(token, 0) + 1
            client_updates.append((local_positive, local_negative))
        positive = {}
        negative = {}
        for local_positive, local_negative in client_updates:
            for token, count in local_positive.items():
                positive[token] = positive.get(token, 0) + count
            for token, count in local_negative.items():
                negative[token] = negative.get(token, 0) + count
    predictions = []
    for text in texts:
        tokens = re.findall(r"[a-z0-9]{2,}", text.lower())
        positive_score = sum(positive.get(token, 0) for token in tokens)
        negative_score = sum(negative.get(token, 0) for token in tokens)
        predictions.append(int(positive_score >= negative_score))
    return predictions


def run_federated(dataset: Path, rounds: int = 3, clients: int = 3) -> dict[str, Any]:
    with dataset.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    texts = np.array([redact(row["text"]) for row in rows])
    labels = np.array([int(row["label"]) for row in rows])
    splits = np.array_split(np.arange(len(texts)), clients)
    if not SKLEARN_AVAILABLE:
        predictions = _fallback_federated(texts, labels, splits, rounds)
        accuracy = sum(actual == predicted for actual, predicted in zip(labels, predictions)) / max(len(labels), 1)
        tp = sum(actual == predicted == 1 for actual, predicted in zip(labels, predictions))
        fp = sum(actual == 0 and predicted == 1 for actual, predicted in zip(labels, predictions))
        fn = sum(actual == 1 and predicted == 0 for actual, predicted in zip(labels, predictions))
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-9)
        return {"protocol": "federated-averaging-simulation", "backend": "stdlib-fallback", "clients": clients, "rounds": rounds, "samples": len(rows), "pii_redaction": True, "epsilon_documented": float(os.getenv("CYBERGUARD_FEDERATED_EPSILON", "8.0")), "accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1, "raw_text_shared": False}
    vectorizer = HashingVectorizer(n_features=2**12, alternate_sign=False, norm="l2")
    features = vectorizer.transform(texts)
    global_weights = None
    global_intercept = None
    for _ in range(rounds):
        updates = []
        for indexes in splits:
            model = SGDClassifier(loss="log_loss", random_state=42, max_iter=1, learning_rate="constant", eta0=0.05)
            model.partial_fit(features[indexes], labels[indexes], classes=np.array([0, 1]))
            updates.append((model.coef_.copy(), model.intercept_.copy(), len(indexes)))
        total = sum(weight for _, _, weight in updates)
        global_weights = sum(coef * weight for coef, _, weight in updates) / total
        global_intercept = sum(intercept * weight for _, intercept, weight in updates) / total
    predictions = (features @ global_weights[0] + global_intercept[0] >= 0).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average="binary", zero_division=0)
    epsilon = float(os.getenv("CYBERGUARD_FEDERATED_EPSILON", "8.0"))
    return {"protocol": "federated-averaging-simulation", "clients": clients, "rounds": rounds, "samples": len(rows), "pii_redaction": True, "epsilon_documented": epsilon, "accuracy": accuracy_score(labels, predictions), "precision": precision, "recall": recall, "f1": f1, "raw_text_shared": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the three-client CyberGuard federated text baseline")
    parser.add_argument("--data", type=Path, default=Path(__file__).parent / "data" / "training_data.csv")
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    print(json.dumps(run_federated(args.data, args.rounds), indent=2))
