# CyberGuard Dataset Guide

The bundled `training_data.csv` contains 104 labeled demonstration examples for suspicious (`1`) and benign (`0`) text. It covers phishing, risky URLs, behavioural account takeover, impersonation, deepfake language, and benign counterexamples.

## Evaluation path

For a stronger research evaluation, add properly licensed public records to a separate CSV with these columns:

```text
text,label,category,source,license,split
```

Do not mix external records into the demonstration set without preserving `source`, `license`, and a fixed train/validation/test split. Recommended public sources include licensed phishing feeds, published security-log corpora, and synthetic media benchmarks whose redistribution terms permit research use. Keep hashes and source URLs in a companion manifest when raw artifacts cannot be redistributed.

The current set is intentionally small and synthetic. It is suitable for a repeatable hackathon demo, not a production performance claim. Use `train_model.py` for the text classifier and report per-category precision, recall, F1, false-positive rate, latency, and drift when the larger licensed corpus is available.
