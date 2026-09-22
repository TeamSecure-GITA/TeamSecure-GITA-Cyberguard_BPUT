"""Evaluate labelled media folders.

Expected layout: dataset/{real,fake}/* with image/audio files. The command
records detector mode, confusion matrix and latency; it does not claim a model
is pretrained unless the API returns pretrained_model metadata.
"""
import argparse
import json
import time
from pathlib import Path
from statistics import median

from media_engine import analyze_media


def evaluate(root: Path) -> dict:
    rows = []
    for label_name, label in (("real", 0), ("fake", 1)):
        for path in (root / label_name).rglob("*"):
            if not path.is_file():
                continue
            content = path.read_bytes()
            started = time.perf_counter()
            result = analyze_media(content, "", path.name, "deepfake")
            elapsed = (time.perf_counter() - started) * 1000
            rows.append({"label": label, "prediction": int(result["score"] >= 50), "latency_ms": elapsed, "method": result.get("method"), "pretrained": bool(result.get("pretrained_model"))})
    if not rows:
        raise ValueError("Dataset must contain real/ and fake/ directories with media files")
    tn = sum(row["label"] == 0 and row["prediction"] == 0 for row in rows)
    fp = sum(row["label"] == 0 and row["prediction"] == 1 for row in rows)
    fn = sum(row["label"] == 1 and row["prediction"] == 0 for row in rows)
    tp = sum(row["label"] == 1 and row["prediction"] == 1 for row in rows)
    return {"samples": len(rows), "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp}, "false_positive_rate": fp / max(fp + tn, 1), "accuracy": (tp + tn) / len(rows), "median_latency_ms": median(row["latency_ms"] for row in rows), "p95_latency_ms": sorted(row["latency_ms"] for row in rows)[max(0, round(len(rows) * 0.95) - 1)], "methods": sorted({row["method"] for row in rows}), "pretrained_outputs": sum(row["pretrained"] for row in rows)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate CyberGuard media detectors")
    parser.add_argument("--data", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.data), indent=2))
