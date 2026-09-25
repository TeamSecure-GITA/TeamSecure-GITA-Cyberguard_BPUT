"""Fine-tune a small transformer for the authorised SMS phishing benchmark."""
import argparse
import csv
import json
from pathlib import Path


def train(dataset: Path, output: Path, epochs: int = 1):
    try:
        import numpy as np
        from datasets import Dataset
        from transformers import AutoModelForSequenceClassification, AutoTokenizer, Trainer, TrainingArguments
    except ImportError as error:
        raise SystemExit("Install requirements-ai.txt plus datasets: " + str(error))
    with dataset.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    data = Dataset.from_dict({"text": [row["text"] for row in rows], "label": [int(row["label"]) for row in rows]})
    data = data.class_encode_column("label")
    model_id = "distilbert-base-uncased"
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    encoded = data.map(lambda batch: tokenizer(batch["text"], truncation=True, padding="max_length", max_length=128), batched=True)
    encoded = encoded.train_test_split(test_size=0.2, seed=42, stratify_by_column="label")
    model = AutoModelForSequenceClassification.from_pretrained(model_id, num_labels=2)
    args = TrainingArguments(output_dir=str(output), num_train_epochs=epochs, per_device_train_batch_size=16, per_device_eval_batch_size=32, evaluation_strategy="epoch", save_strategy="epoch", logging_steps=50, report_to=[])
    trainer = Trainer(model=model, args=args, train_dataset=encoded["train"], eval_dataset=encoded["test"], tokenizer=tokenizer)
    trainer.train()
    output.mkdir(parents=True, exist_ok=True)
    trainer.save_model(output)
    tokenizer.save_pretrained(output)
    metrics = trainer.evaluate()
    (output / "training-metadata.json").write_text(json.dumps({"base_model": model_id, "dataset": str(dataset), "samples": len(rows), "epochs": epochs, "metrics": metrics}, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "models" / "text-transformer")
    parser.add_argument("--epochs", type=int, default=1)
    args = parser.parse_args()
    train(args.data, args.output, args.epochs)
