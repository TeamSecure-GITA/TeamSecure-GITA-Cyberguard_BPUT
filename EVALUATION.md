# CYBERGUARD Evaluation

## Current implementation status

This document supersedes the original 104-row-only assessment. The repository now includes QR decoding, EML authentication analysis, SSRF-safe website inspection, Isolation Forest login scoring, pretrained image/audio adapters, sampled video-frame inference, entity/campaign graph analytics, an OpenAI-compatible analyst assistant with offline fallback, Flower federation entry points, and Locust load-test scenarios.

## Trained Text Model

The baseline text model uses a TF-IDF vectorizer with word unigrams/bigrams and Logistic Regression. The training command is:

```powershell
cd cyberguard-backend
.\venv\Scripts\python.exe train_model.py
```

The bundled demonstration dataset contains 104 labeled examples covering phishing, URL intelligence, behavioural account takeover, impersonation, deepfake language, and benign counterexamples. Its original fixed holdout evaluation was:

- Accuracy: 84.6%
- Suspicious-class precision: 77.8%
- Suspicious-class recall: 100%
- Suspicious-class F1: 87.5%

These figures are only a baseline because the bundled examples are synthetic and the expanded set intentionally favors catching suspicious activity. Production evaluation must use a separated, verified, representative dataset and should report precision, recall, F1, confusion matrix, false-positive rate, inference latency, and drift over time.

The current live text artifact is trained from the authorised UCI SMS Spam Collection snapshot when `threat_text_model_fallback.json` is present. It is loaded by the detector when the joblib model is unavailable.

## UCI SMS benchmark result

The checked-in result at `cyberguard-backend/data/uci-sms-results.json` contains 5,574 messages with a stratified 1,394-message holdout. On this Windows host the standard-library fallback backend was used because scikit-learn's OpenMP helper was blocked. Results: TN=688, FP=9, FN=409, TP=288, precision=96.97%, recall=41.32%, F1=57.95%, false-positive rate=1.29%, and approximately 0.019 ms per sample. ROC-AUC is unavailable in fallback mode. The low recall is a known model-quality limitation, not hidden by the dashboard.

## Reproducible evaluation workflow

`evaluate_public_datasets.py` accepts an authorised CSV snapshot with `text,label` columns and writes the required confusion matrix, false-positive rate, ROC-AUC, PR-AUC, and median/p95 inference latency:

```powershell
cd cyberguard-backend
python evaluate_public_datasets.py --data path\to\authorised\dataset.csv --output evaluation-results.json
```

Do not report the bundled 104 synthetic examples as public-data performance. Preserve the dataset licence, source URL, collection date, deduplication policy, and untouched test split beside each generated result.

## Pretrained media evaluation

The image and audio adapters in `deepfake_models.py` load the cached Hugging Face weights under `models/pretrained`; video samples frames and reuses the image detector. `/api/v1/models/status` reports cached weights, loaded modalities, and runtime errors. The current model outputs are pretrained inference, but not production-calibrated deepfake claims. Before consequential use, calibrate all modalities on authorised holdouts and publish per-modality confusion matrices, ROC-AUC, PR-AUC, and p95 latency.

## Graph analytics

`/api/v1/dashboard/graph` extracts domains, IPs, email addresses, incident categories, and incident nodes from the last 100 incidents. It returns weighted edges, connected-component campaign communities, and analytics counts. This is a deterministic explainable campaign baseline; a large-scale Neo4j/Louvain deployment is not claimed.

## Federated and analyst-assistant workflows

`federated_training.py` simulates three institutions using federated averaging over hashed features. It redacts email addresses and long numeric identifiers and does not share raw text. `CYBERGUARD_FEDERATED_EPSILON` records the declared privacy budget; this is a simulation until a Flower deployment is configured.

`POST /api/v1/assistant/analyze` sends only redacted structured evidence to an OpenAI-compatible endpoint when `CYBERGUARD_LLM_ENDPOINT`, `CYBERGUARD_LLM_API_KEY`, and `CYBERGUARD_LLM_MODEL` are configured. With no provider configured it returns an explicitly labelled offline template. The rules and classifiers remain the decision-makers.

## Demonstration Scenarios

1. Phishing/social engineering: urgency, credential request, and look-alike URL.
2. URL intelligence: lexical entropy, risky TLDs, redirect shorteners, redirect parameters, raw IP hosts, IDN hosts, and look-alike domains.
3. Behavioural ATO: structured JSON telemetry, password spraying, impossible travel, MFA fatigue, new-device activity, and failed-attempt bursts.
4. Digital impersonation/deepfake: lightweight image/audio anomaly scoring, synthetic-media language, authority impersonation, and sender spoofing.
5. Technical threat: failed authentication, port scanning, API abuse, malware, or exfiltration telemetry.

## Presentation scenarios

The application includes exactly three one-click scenarios in the Threat Inspector and the authenticated `seed_demo_data.py` script:

1. Deepfake authority message.
2. Behavioural account takeover with structured login telemetry.
3. Look-alike URL with redirect chain and contact mismatch.

IOC results include local reputation and risk enrichment. Set `CYBERGUARD_THREAT_INTEL_URL` to call an external provider; otherwise the engine uses transparent local heuristics and blocklists.

## Operational Measures

- API persistence: SQLite incident and action history.
- Authorization: Analyst inspection and Lead response execution.
- Scalability path: replace SQLite with PostgreSQL, move sessions to Redis, and run the stateless FastAPI service behind a load balancer.
- Deployment path: containerize backend/frontend, terminate TLS at the ingress, add structured logging, rate limits, secret management, and a SIEM connector.
