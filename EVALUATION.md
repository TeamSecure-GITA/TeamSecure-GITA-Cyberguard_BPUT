# CYBERGUARD Evaluation

## Trained Text Model

The baseline text model uses a TF-IDF vectorizer with word unigrams/bigrams and Logistic Regression. The training command is:

```powershell
cd cyberguard-backend
.\venv\Scripts\python.exe train_model.py
```

The bundled demonstration dataset contains 104 labeled examples covering phishing, URL intelligence, behavioural account takeover, impersonation, deepfake language, and benign counterexamples. The current fixed holdout evaluation is:

- Accuracy: 84.6%
- Suspicious-class precision: 77.8%
- Suspicious-class recall: 100%
- Suspicious-class F1: 87.5%

These figures are only a baseline because the bundled examples are synthetic and the expanded set intentionally favors catching suspicious activity. Production evaluation must use a separated, verified, representative dataset and should report precision, recall, F1, confusion matrix, false-positive rate, inference latency, and drift over time.

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
