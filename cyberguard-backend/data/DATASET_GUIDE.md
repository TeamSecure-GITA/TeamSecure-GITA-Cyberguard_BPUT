# CyberGuard Dataset Guide

The bundled `training_data.csv` contains 104 labeled demonstration examples for suspicious (`1`) and benign (`0`) text. It covers phishing, risky URLs, behavioural account takeover, impersonation, deepfake language, and benign counterexamples.

## Evaluation path

For a stronger research evaluation, add properly licensed public records to a separate CSV with these columns:

```text
text,label,category,source,license,split
```

Do not mix external records into the demonstration set without preserving `source`, `license`, and a fixed train/validation/test split. Recommended public sources include licensed phishing feeds, published security-log corpora, and synthetic media benchmarks whose redistribution terms permit research use. Keep hashes and source URLs in a companion manifest when raw artifacts cannot be redistributed.

The current set is intentionally small and synthetic. It is suitable for a repeatable hackathon demo, not a production performance claim. Use `train_model.py` for the text classifier and report per-category precision, recall, F1, false-positive rate, latency, and drift when the larger licensed corpus is available.

For category-specific evaluation on an authorised corpus, prepare three separate CSV manifests with `text,label,category,source,license,split` columns and `split` values `train`, `calibration`, or `test`. Keep benign and suspicious examples for each category in every split. Run `evaluate_public_datasets.py --train-data data/train.csv --calibration-data data/calibration.csv --test-data data/test.csv --output data/category-results.json`. The evaluator trains one baseline per category, chooses a probability threshold from calibration data under a false-positive-rate ceiling, rejects normalized exact-text duplicates across splits, and reports metrics only on the untouched test split. It records provenance fields but cannot independently verify license terms or detect semantic near-duplicates; review dataset provenance and grouping before relying on the results. The simpler `--data` command remains a seeded exploratory holdout and must not be presented as an untouched final benchmark.

## UCI SMS Spam Collection snapshot

`download_public_dataset.py` retrieves the UCI SMS Spam Collection from the UCI Machine Learning Repository and normalizes it to `text,label`. The downloaded snapshot contains 5,574 messages. Run:

```powershell
python data/download_public_dataset.py --output data/uci_sms_spam.csv
python evaluate_public_datasets.py --data data/uci_sms_spam.csv --output data/uci-sms-results.json
```

An earlier fallback-only run used a stratified 75/25 split and reported TN=688, FP=9, FN=409, TP=288, precision=96.97%, recall=41.32%, F1=57.95%, FPR=1.29%, and approximately 0.019 ms/sample. ROC-AUC was unavailable in fallback mode. This is a historical result for that fallback and split; it is not the current scikit-learn benchmark below.

The current checked-in result in `uci-sms-results.json` uses a seeded scikit-learn baseline on a stratified 1,394-message holdout: TN=1,207, FP=0, FN=47, TP=140, precision=100%, recall=74.87%, F1=85.63%, FPR=0%, ROC-AUC=0.993, PR-AUC=0.979, median latency=0.37 ms, and p95 latency=0.80 ms per sample. The evaluator trains its own model on the split, so these metrics are not a guarantee for the deployed model artifact. Both results are SMS-only and must not be presented as performance on email, URLs, logs, or media.
