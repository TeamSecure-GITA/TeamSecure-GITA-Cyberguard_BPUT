# CyberGuard Dataset Guide

The bundled `training_data.csv` contains 104 labeled demonstration examples for suspicious (`1`) and benign (`0`) text. It covers phishing, risky URLs, behavioural account takeover, impersonation, deepfake language, and benign counterexamples.

## Evaluation path

For a stronger research evaluation, add properly licensed public records to a separate CSV with these columns:

```text
text,label,category,source,license,split
```

Do not mix external records into the demonstration set without preserving `source`, `license`, and a fixed train/validation/test split. Recommended public sources include licensed phishing feeds, published security-log corpora, and synthetic media benchmarks whose redistribution terms permit research use. Keep hashes and source URLs in a companion manifest when raw artifacts cannot be redistributed.

The current set is intentionally small and synthetic. It is suitable for a repeatable hackathon demo, not a production performance claim. Use `train_model.py` for the text classifier and report per-category precision, recall, F1, false-positive rate, latency, and drift when the larger licensed corpus is available.

## UCI SMS Spam Collection snapshot

`download_public_dataset.py` retrieves the UCI SMS Spam Collection from the UCI Machine Learning Repository and normalizes it to `text,label`. The downloaded snapshot contains 5,574 messages. Run:

```powershell
python data/download_public_dataset.py --output data/uci_sms_spam.csv
python evaluate_public_datasets.py --data data/uci_sms_spam.csv --output data/uci-sms-results.json
```

The first local benchmark used a stratified 75/25 split and the standard-library fallback because the host blocked scikit-learn's OpenMP DLL: TN=688, FP=9, FN=409, TP=288, precision=96.97%, recall=41.32%, F1=57.95%, FPR=1.29%, and approximately 0.019 ms/sample. ROC-AUC was unavailable in fallback mode. These results expose the model's high precision but poor recall on real SMS data; do not present the synthetic baseline as production performance.
