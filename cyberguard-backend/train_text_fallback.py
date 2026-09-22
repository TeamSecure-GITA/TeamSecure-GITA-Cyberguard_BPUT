"""Train a dependency-light multinomial text model for restricted hosts."""
import argparse
import csv
import json
import math
import re
from pathlib import Path


def tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]{2,}", text.lower())


def train(dataset: Path, output: Path) -> dict:
    with dataset.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    class_docs = {"0": 0, "1": 0}
    counts = {"0": {}, "1": {}}
    vocabulary = set()
    for row in rows:
        label = str(int(row["label"]))
        words = set(tokens(row["text"]))
        class_docs[label] += 1
        vocabulary.update(words)
        for word in words:
            counts[label][word] = counts[label].get(word, 0) + 1
    total_docs = sum(class_docs.values())
    model = {"algorithm": "bernoulli-naive-bayes", "samples": total_docs, "vocabulary": sorted(vocabulary), "priors": {label: count / total_docs for label, count in class_docs.items()}, "likelihoods": {}}
    for label in ("0", "1"):
        denominator = class_docs[label] + 2
        model["likelihoods"][label] = {word: (counts[label].get(word, 0) + 1) / denominator for word in vocabulary}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(model), encoding="utf-8")
    return {"algorithm": model["algorithm"], "samples": total_docs, "vocabulary": len(vocabulary), "output": str(output)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "models" / "threat_text_model_fallback.json")
    args = parser.parse_args()
    print(json.dumps(train(args.data, args.output), indent=2))
