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
DEFAULT_DATASET = BASE_DIR / "data" / "training_data.csv"
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


def train(dataset_path: Path, output_path: Path):
    texts, labels = load_dataset(dataset_path)
    train_texts, test_texts, train_labels, test_labels = train_test_split(
        texts, labels, test_size=0.25, random_state=42, stratify=labels
    )
    model = Pipeline([
        ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1)),
        ("classifier", LogisticRegression(max_iter=1000, random_state=42)),
    ])
    model.fit(train_texts, train_labels)
    predictions = model.predict(test_texts)
    report = classification_report(test_labels, predictions, output_dict=True, zero_division=0)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)
    metrics = {
        "dataset": str(dataset_path),
        "samples": len(texts),
        "accuracy": accuracy_score(test_labels, predictions),
        "classification_report": report,
        "model": str(output_path),
    }
    print(json.dumps(metrics, indent=2))
    return model


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the CYBERGUARD text threat classifier.")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATASET, help="CSV file with text,label columns")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output joblib model path")
    args = parser.parse_args()
    train(args.data, args.output)
