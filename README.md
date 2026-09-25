# CyberGuard

CyberGuard is an AI-assisted SOC platform for phishing, malicious URLs, digital impersonation, synthetic media triage, account takeover, and cyber-threat response. It combines deterministic evidence rules with a TF-IDF text model, media anomaly scoring, explainable risk factors, MITRE ATT&CK mapping, RBAC, incident workflow, SIEM ingest, and audited response simulation.

## What works

- FastAPI backend and React/Vite SOC dashboard
- Email, SMS, URL, image, audio, video, authentication, system, network, API, malware, and exfiltration analysis
- QR-code extraction from image uploads and safe URL re-analysis
- `.eml` parsing with SPF, DKIM, DMARC, From, Reply-To, and Return-Path checks
- SSRF-safe website inspection with DNS private-range blocking, bounded redirects, size limits, and password-form detection
- Isolation Forest login anomaly scoring for structured authentication telemetry
- Weighted XAI indicators, plain-language explanations, scoring formula, IOC enrichment, and MITRE techniques
- Declarative YAML playbook validation and approval-aware dry-run planning
- Optional pretrained image/audio detector adapters with explicit model and calibration status
- Optional OpenAI-compatible analyst assistant with PII redaction and offline fallback
- Three-client federated text-training simulation with no raw-text sharing
- Reproducible public-dataset evaluation CLI with confusion matrix, FPR, ROC-AUC, PR-AUC, and latency
- JWT sessions, role-based response controls, audit logging, incident lifecycle, Docker, and Render deployment

## Run locally

### Backend

```powershell
cd cyberguard-backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:CYBERGUARD_JWT_SECRET = 'replace-with-a-long-random-local-secret'
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend

```powershell
cd cyberguard-frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173`. The local demo accounts are created by the backend database initializer: `lead` / `lead123` and `analyst` / `analyst123`. Change all demo credentials before deployment.

### Optional AI integrations

Install the separately licensed/operational dependencies only when the host can run them:

```powershell
cd cyberguard-backend
pip install -r requirements-ai.txt
$env:CYBERGUARD_ENABLE_PRETRAINED_MEDIA = 'true'
```

The image and audio model IDs are configurable in `.env`. `/api/v1/models/status` reports whether weights actually loaded. The analyst assistant uses `CYBERGUARD_LLM_ENDPOINT`, `CYBERGUARD_LLM_API_KEY`, and `CYBERGUARD_LLM_MODEL`; without them it returns a clearly labelled offline template.

Download the configured public weights after reviewing their licences:

```powershell
pip install -r requirements-ai.txt
python download_pretrained_models.py
$env:CYBERGUARD_ENABLE_PRETRAINED_MEDIA = 'true'
```

Run the federated simulation and evaluation against an authorised CSV snapshot:

```powershell
python federated_training.py --data data/training_data.csv
python evaluate_public_datasets.py --data data/training_data.csv --output evaluation-results.json
python data/download_public_dataset.py --output data/uci_sms_spam.csv
python evaluate_public_datasets.py --data data/uci_sms_spam.csv --output data/uci-sms-results.json
python evaluate_media_dataset.py --data path\to\authorised\media-dataset
```

For submission, replace the bundled demonstration CSV with licensed public snapshots and preserve their licence, collection date, split, and results file. The evaluation script never downloads data implicitly.

For a real Flower run, start one server and three clients with separate institution datasets:

```powershell
python flower_federated.py server --rounds 3
python flower_federated.py client --data institution-a.csv
python flower_federated.py client --data institution-b.csv

The repository also includes a local four-container profile using the three sample institution files:

```powershell
python flower_federated.py client --data institution-c.csv
```

Replace the sample institution files with approved, disjoint datasets before treating the federated result as meaningful.
```

For load testing, install `requirements-dev.txt`, start the API, and run `locust -f locustfile.py --host http://127.0.0.1:8000`.

### Docker

Docker Compose runs in production mode and intentionally refuses to start without `CYBERGUARD_JWT_SECRET`:

```powershell
$env:CYBERGUARD_JWT_SECRET = 'replace-with-a-long-random-secret'
docker compose up --build
```

## Key API routes

- `POST /api/v1/analyze` and `/api/v1/analyze/file`
- `POST /api/v1/analyze/website`
- `GET /api/v1/incidents/{id}/explainability`
- `GET /api/v1/playbooks` and `POST /api/v1/playbooks/plan`
- `POST /api/v1/response/execute`
- `POST /api/v1/siem/log`

Interactive API documentation is available at `http://127.0.0.1:8000/docs` while the backend is running.

## Evaluation notes

The bundled text model is a baseline trained on the demonstration dataset in `cyberguard-backend/data/training_data.csv`. It is not a substitute for evaluation on authorised public datasets. Before submission, run a dated benchmark using SMS Spam Collection, authorised URL feeds, and suitable intrusion/deepfake datasets; publish confusion matrices, false-positive rate, ROC/PR metrics, and p50/p95 latency in `EVALUATION.md`.

The media detectors currently provide calibrated triage signals, not a claim of forensic deepfake proof. Analysts should use the displayed evidence and the `verify manually` decision path before taking consequential action.

## Architecture and security

See [ARCHITECTURE.md](ARCHITECTURE.md) for the data flow. Uploads are bounded by `CYBERGUARD_MAX_UPLOAD_BYTES`; website inspection rejects private and reserved addresses and validates every redirect; response actions are allowlisted and lead-controlled; YAML playbooks are dry-run/approval aware and cannot execute shell commands.
