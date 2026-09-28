# CYBERGUARD Evaluation

## Current implementation status

This document supersedes the original 104-row-only assessment. The repository now includes QR decoding, EML authentication analysis, SSRF-safe website inspection, Isolation Forest login scoring, pretrained image/audio adapters, sampled video-frame inference, entity/campaign graph analytics, an OpenAI-compatible analyst assistant with offline fallback, Flower federation entry points, and Locust load-test scenarios.

Uploaded EML files include sender-domain alignment checks across visible From, Reply-To, Return-Path, SPF, DKIM, and DMARC evidence. Set `CYBERGUARD_TRUSTED_AUTHSERV_IDS` to a comma-separated list of trusted receiving mail-server authserv IDs before a passing `Authentication-Results` header can produce a verified result; untrusted headers are explicitly reported and do not lower the identity risk score. This checks domain-authentication consistency, not a person's legal identity.

## Trained Text Model

The baseline text model uses a TF-IDF vectorizer with word unigrams/bigrams and Logistic Regression. The training command is:

```powershell
cd cyberguard-backend
.\venv\Scripts\python.exe train_model.py
```

The live detector applies the model score at `CYBERGUARD_TEXT_MODEL_THRESHOLD` (default 50, range 0-100). Tune this only on a separate calibration set; do not optimize the reported holdout.

The bundled demonstration dataset contains 104 labeled examples covering phishing, URL intelligence, behavioural account takeover, impersonation, deepfake language, and benign counterexamples. Its original fixed holdout evaluation was:

- Accuracy: 84.6%
- Suspicious-class precision: 77.8%
- Suspicious-class recall: 100%
- Suspicious-class F1: 87.5%

These figures are only a baseline because the bundled examples are synthetic and the expanded set intentionally favors catching suspicious activity. Production evaluation must use a separated, verified, representative dataset and should report precision, recall, F1, confusion matrix, false-positive rate, inference latency, and drift over time.

The live joblib artifact is trained by default from the authorised UCI SMS Spam Collection snapshot. `train_model.py` evaluates a stratified 25% holdout, then refits the saved artifact on all dataset rows. The dependency-light fallback can be regenerated with `python train_text_fallback.py --data data/uci_sms_spam.csv`; it is used only when the joblib artifact is unavailable.

## UCI SMS benchmark result

The checked-in result at `cyberguard-backend/data/uci-sms-results.json` contains 5,574 messages with a stratified 1,394-message holdout. The current scikit-learn run at the default 50% threshold reports TN=1,207, FP=0, FN=47, TP=140, precision=100%, recall=74.87%, F1=85.63%, false-positive rate=0%, ROC-AUC=0.993, PR-AUC=0.979, median inference latency=0.37 ms, and p95 latency=0.80 ms per sample. This evaluator trains its own seeded baseline on the dataset split; it is not a validated performance guarantee for the deployed model artifact. Select thresholds on a separate calibration split and preserve a final untouched holdout.

## Reproducible evaluation workflow

`evaluate_public_datasets.py` accepts an authorised CSV snapshot with `text,label` columns and writes the required confusion matrix, false-positive rate, ROC-AUC, PR-AUC, fit time, and measured median/p95 per-sample inference latency. `--threshold` accepts a 0-100 probability cutoff:

```powershell
cd cyberguard-backend
python evaluate_public_datasets.py --data path\to\authorised\dataset.csv --output evaluation-results.json
```

Do not report the bundled 104 synthetic examples as public-data performance. Preserve the dataset licence, source URL, collection date, deduplication policy, and untouched test split beside each generated result.

## Pretrained media evaluation

The image and audio adapters in `deepfake_models.py` load the cached Hugging Face weights under `models/pretrained`; video samples frames and reuses the image detector. `/api/v1/models/status` reports cached weights, loaded modalities, and runtime errors. Cross-modal comparison requires at least two distinct image/audio/video channels with valid anomaly scores; its authenticity score is an inverse risk proxy, not a probability or production-calibrated deepfake claim. Before consequential use, calibrate all modalities on authorised holdouts and publish per-modality confusion matrices, ROC-AUC, PR-AUC, and p95 latency.

`evaluate_media_dataset.py --data path\to\authorised\media --threshold 50` evaluates `real/` and `fake/` folders and reports confusion matrix, precision, recall, F1, specificity, ROC-AUC, PR-AUC, and latency. It requires both classes. Select a threshold only on a separate calibration split; keep the final evaluation holdout untouched.

## Graph analytics

`/api/v1/dashboard/graph` extracts domains, IPs, email addresses, incident categories, and incident nodes from the last 100 incidents. It returns weighted edges, connected-component campaign communities, and analytics counts. Attacker-intent and fingerprint-drift summaries require shared IOC/ATT&CK evidence or strong payload similarity rather than same-category matches alone. This is a deterministic explainable campaign baseline; a large-scale Neo4j/Louvain deployment is not claimed.

## Federated and analyst-assistant workflows

`federated_training.py` simulates three institutions using federated averaging over hashed features. `flower_federated.py` provides a networked Flower server/client entry point; each client redacts email addresses and long numeric identifiers before feature extraction and keeps raw text local. For cross-host deployment, start the server with `python flower_federated.py server --bind-address 0.0.0.0:8080 --min-clients 3 --ca-cert ca.pem --server-cert server.pem --server-key server-key.pem`, then launch one client per institution with `python flower_federated.py client --server-address <reachable-server-host>:8080 --root-cert ca.pem --data <local-authorised.csv>`. Plaintext is rejected for non-loopback addresses unless `--allow-insecure` is explicitly supplied for isolated demos. `CYBERGUARD_FLOWER_BIND_ADDRESS` and `CYBERGUARD_FLOWER_SERVER_ADDRESS` can set deployment defaults. TLS encrypts transport but does not provide secure aggregation or differential privacy; restrict client access at the network boundary and validate model-update leakage before using sensitive data. `CYBERGUARD_FEDERATED_EPSILON` in the simulation is a documented value, not an implemented privacy guarantee.

`docker compose -f docker-compose.flower.yml up --build` is an isolated plaintext demo only: clients connect to `flower-server` over the private Compose network and port 8080 is published only on host loopback. Do not expose that demo configuration to institutional networks.

`POST /api/v1/assistant/analyze` sends only redacted structured evidence to an OpenAI-compatible endpoint when `CYBERGUARD_LLM_ENDPOINT`, `CYBERGUARD_LLM_API_KEY`, and `CYBERGUARD_LLM_MODEL` are configured. With no provider configured it returns an explicitly labelled offline template. The rules and classifiers remain the decision-makers.

Head administrators can create a Jira/ServiceNow ticket through `POST /api/v1/integrations/tickets`. Jira Cloud requires `CYBERGUARD_JIRA_URL`, `CYBERGUARD_JIRA_EMAIL`, `CYBERGUARD_JIRA_TOKEN`, and `CYBERGUARD_JIRA_PROJECT`; the account email and API token are sent with HTTP Basic authentication. `POST /api/v1/integrations/identity/disable` and `/api/v1/integrations/endpoint/isolate` require an explicit `confirmed: true` body field before calling Okta/Microsoft Graph or the configured EDR endpoint. Provider calls need real credentials and are not live-tested in this environment.

Shared-immunity publishing requires `CYBERGUARD_TENANT_IMMUNITY_URL`, `CYBERGUARD_TENANT_IMMUNITY_SECRET`, and a stable installation-specific `CYBERGUARD_TENANT_ID`. Only 64-character opaque signatures are sent; the tenant ID is HMAC-pseudonymized before transmission. Incidents without a fingerprint, IOC, or ATT&CK technique do not produce a shareable signature.

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

- API persistence: local/development Compose uses SQLite; `docker-compose.prod.yml` starts PostgreSQL and configures `CYBERGUARD_DATABASE_URL` for the API and worker. PostgreSQL schema creation is automatic at startup; live service and restore drills still require deployment validation.
- SIEM history: normalized SIEM events, demo-seed state, and IdP correlation are stored in the configured application database rather than process-local memory.
- Alert feedback: analyst outcomes and reviewer identity are persisted in the configured application database; the API attributes reviews to the authenticated account.
- CVE compliance: successful feed syncs preserve severity details, persist the latest snapshot, and refresh the compliance diff; string-only legacy entries are counted but do not create severity-based gaps.
- Threat immune memory: only closed and mitigated incidents are eligible historical matches; normalized exact repeats are retained as valid matches.
- Fatigue-aware routing: active assigned incidents contribute to analyst load, closed/mitigated incidents are excluded from the queue, and an empty roster returns an explicit unassigned target.
- Jurisdiction routing: analysis stores only optional country/region metadata for text, file, and website incidents; missing residency is reported as unknown/global review rather than guessed.
- Ephemeral state: OTP/passkey challenges and protected-path rate windows use process memory by default in development. Production startup requires `CYBERGUARD_REDIS_URL` to share expiring, one-time state across API instances; a missing or unavailable Redis service fails startup instead of silently falling back to local memory.
- Dashboard targeting summary: `/api/v1/dashboard/metrics` reports up to eight recurring email identities, URL hosts, and source networks from the latest 500 incidents. Email local-parts and IPv4 host octets are masked; counts are per incident, not per repeated indicator.
- Authorization: Analyst inspection and Lead response execution.
- Scalability path: production Compose uses PostgreSQL and Redis; horizontal API replicas still require an external load balancer, shared uploads/artifacts, and tested connection-pool limits.
- Deployment path: containerize backend/frontend, terminate TLS at the ingress, add structured logging, rate limits, secret management, and a SIEM connector.
