"""Evaluate labelled media folders.

Expected layout: dataset/{real,fake}/* with image/audio files. The command
records detector mode, confusion matrix and latency; it does not claim a model
is pretrained unless the API returns pretrained_model metadata.
"""
import argparse
import hashlib
import json
import os
import time
from pathlib import Path
from statistics import median

from media_engine import analyze_media


def _manifest(root: Path, required: bool) -> dict:
    manifest_path = root / "dataset-manifest.json"
    if not manifest_path.exists():
        if required:
            raise ValueError("Production evaluation requires dataset-manifest.json with source, licence, collection_date, and split fields")
        return {"status": "missing", "path": str(manifest_path)}
    metadata = json.loads(manifest_path.read_text(encoding="utf-8"))
    required_fields = {"source", "licence", "collection_date", "split"}
    missing = sorted(required_fields - metadata.keys())
    if missing:
        raise ValueError(f"Dataset manifest is missing required fields: {', '.join(missing)}")
    return {"status": "verified", "path": str(manifest_path), "sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(), "metadata": metadata}


def _collect(root: Path) -> list[dict]:
    rows = []
    for label_name, label in (("real", 0), ("fake", 1)):
        for path in (root / label_name).rglob("*"):
            if not path.is_file():
                continue
            content = path.read_bytes()
            started = time.perf_counter()
            result = analyze_media(content, "", path.name, "deepfake")
            elapsed = (time.perf_counter() - started) * 1000
            rows.append({"label": label, "score": result["score"], "prediction": int(result["score"] >= threshold), "latency_ms": elapsed, "method": result.get("method"), "pretrained": bool(result.get("pretrained_model"))})
    if not rows:
        raise ValueError("Dataset must contain real/ and fake/ directories with media files")
    return rows


def _metrics(rows: list[dict], threshold: int) -> dict:
    for row in rows:
        row["prediction"] = int(row["score"] >= threshold)
    tn = sum(row["label"] == 0 and row["prediction"] == 0 for row in rows)
    fp = sum(row["label"] == 0 and row["prediction"] == 1 for row in rows)
    fn = sum(row["label"] == 1 and row["prediction"] == 0 for row in rows)
    tp = sum(row["label"] == 1 and row["prediction"] == 1 for row in rows)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    return {"samples": len(rows), "threshold": threshold, "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp}, "false_positive_rate": fp / max(fp + tn, 1), "accuracy": (tp + tn) / len(rows), "precision": precision, "recall": recall, "f1": f1, "median_latency_ms": median(row["latency_ms"] for row in rows), "p95_latency_ms": sorted(row["latency_ms"] for row in rows)[max(0, round(len(rows) * 0.95) - 1)], "methods": sorted({row["method"] for row in rows}), "pretrained_outputs": sum(row["pretrained"] for row in rows)}


def calibrate(validation_rows: list[dict], fpr_budget: float) -> tuple[int, dict]:
    candidates = [(threshold, _metrics([dict(row) for row in validation_rows], threshold)) for threshold in range(1, 100)]
    eligible = [(threshold, result) for threshold, result in candidates if result["false_positive_rate"] <= fpr_budget]
    if not eligible:
        raise ValueError(f"No threshold meets the configured validation FPR budget of {fpr_budget:.3f}")
    threshold, result = max(eligible, key=lambda item: (item[1]["f1"], item[1]["recall"], -item[0]))
    return threshold, {"method": "validation-grid-search", "fpr_budget": fpr_budget, "validation_metrics": result}


def evaluate(root: Path, threshold: int = 50, calibrated: bool = False, require_provenance: bool = False, fpr_budget: float = 0.05) -> dict:
    provenance = _manifest(root, require_provenance)
    validation_root = root / "validation"
    test_root = root / "test"
    calibration = {"status": "not-calibrated", "warning": "Use --calibrate with separate validation/ and test/ splits before production."}
    if calibrated:
        if not validation_root.is_dir() or not test_root.is_dir():
            raise ValueError("Calibration requires separate validation/ and test/ directories, each containing real/ and fake/")
        validation_rows = _collect(validation_root)
        threshold, calibration = calibrate(validation_rows, fpr_budget)
        rows = _collect(test_root)
        calibration["status"] = "calibrated-on-validation-split"
    else:
        rows = _collect(root)
    result = _metrics(rows, threshold)
    result["calibration"] = calibration
    result["provenance"] = provenance
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate CyberGuard media detectors")
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--threshold", type=int, default=50)
    parser.add_argument("--calibrate", action="store_true")
    parser.add_argument("--require-provenance", action="store_true")
    parser.add_argument("--fpr-budget", type=float, default=float(os.getenv("CYBERGUARD_MEDIA_FPR_BUDGET", "0.05")))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(evaluate(args.data, args.threshold, args.calibrate, args.require_provenance, args.fpr_budget), indent=2)
    print(result)
    if args.output:
        args.output.write_text(result + "\n", encoding="utf-8")
