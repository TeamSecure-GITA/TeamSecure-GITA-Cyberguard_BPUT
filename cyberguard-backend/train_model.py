import argparse
import csv
import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

BASE_DIR = Path(__file__).parent
DEFAULT_DATASET = BASE_DIR / "data" / "uci_sms_spam.csv"
DEFAULT_OUTPUT = BASE_DIR / "models" / "threat_text_model.joblib"


def load_dataset(path: Path):
    with path.open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    if not rows or not {"text", "label"}.issubset(rows[0]):
        raise ValueError("Dataset must contain text and label columns.")
    texts = [row["text"].strip() for row in rows if row["text"].strip()]
    labels = [int(row["label"]) for row in rows if row["text"].strip()]
    if len(set(labels)) < 2:
        raise ValueError("Dataset must contain at least two label classes.")
    return texts, labels


def train(dataset_path: Path, output_path: Path, metrics_path: Path | None = None):
    texts, labels = load_dataset(dataset_path)
    train_texts, test_texts, train_labels, test_labels = train_test_split(
        texts, labels, test_size=0.25, random_state=42, stratify=labels
    )
    evaluation_model = _build_model()
    evaluation_model.fit(train_texts, train_labels)
    predictions = evaluation_model.predict(test_texts)
    report = classification_report(test_labels, predictions, output_dict=True, zero_division=0)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(evaluation_model, output_path)
    metrics = {
        "dataset": str(dataset_path),
        "samples": len(texts),
        "evaluation_training_samples": len(train_texts),
        "evaluation_holdout_samples": len(test_texts),
        "artifact_training_samples": len(train_texts),
        "artifact_is_holdout_evaluated": True,
        "holdout_reused_for_artifact_training": False,
        "accuracy": accuracy_score(test_labels, predictions),
        "classification_report": report,
        "model": str(output_path),
    }
    serialized_metrics = json.dumps(metrics, indent=2)
    if metrics_path:
        metrics_path.parent.mkdir(parents=True, exist_ok=True)
        metrics_path.write_text(serialized_metrics + "\n", encoding="utf-8")
    print(serialized_metrics)
    return evaluation_model


def _build_model():
    return Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1)),
        ("classifier", LogisticRegression(max_iter=1000, random_state=42)),
    ])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the CYBERGUARD text threat classifier.")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATASET, help="CSV file with text,label columns")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output joblib model path")
    parser.add_argument("--metrics-output", type=Path, help="Optional JSON file for holdout metrics")
    args = parser.parse_args()
    train(args.data, args.output, args.metrics_output)
