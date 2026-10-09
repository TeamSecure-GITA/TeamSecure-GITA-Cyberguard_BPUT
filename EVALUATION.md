# CYBERGUARD Evaluation

## Current implementation status

This document supersedes the original 104-row-only assessment. The repository now includes QR decoding, EML authentication analysis, SSRF-safe website inspection, Isolation Forest login scoring, pretrained image/audio adapters, sampled video-frame inference, entity/campaign graph analytics, an OpenAI-compatible analyst assistant with offline fallback, Flower federation entry points, and Locust load-test scenarios.

Uploaded EML files include sender-domain alignment checks across visible From, Reply-To, Return-Path, SPF, DKIM, and DMARC evidence. Bounded text attachments are included in text analysis, all attachment bytes are SHA-256 hashed, and potentially active extensions are flagged for review. Each attachment is also scanned with the bundled YARA rules when the optional YARA runtime is installed; match, no-match, unavailable, and scan-error outcomes are exposed in the assessment. ZIP entries are scanned in memory without filesystem extraction, with limits on entries, per-member and aggregate decompressed bytes, compression ratio, and nested archive depth; skipped members are explicitly reported. Other archive formats are not unpacked. This is signature triage, not antivirus, and a no-match result does not establish that a file is safe. Set `CYBERGUARD_TRUSTED_AUTHSERV_IDS` to a comma-separated list of trusted receiving mail-server authserv IDs before a passing `Authentication-Results` header can produce a verified result; untrusted headers are explicitly reported and do not lower the identity risk score. This checks domain-authentication consistency, not a person's legal identity.

Website inspection exposes verified TLS issuer, issue/expiry times, certificate age, and remaining validity. A certificate with 14 or fewer days remaining adds risk. Optional RDAP registration-age enrichment is disabled by default; enable it with `CYBERGUARD_ENABLE_RDAP=true` to send the analyzed public domain to `rdap.org`. Domains registered within 30 days add risk. DOM analysis flags known-brand claims paired with a credential form on an unrelated domain and credential submissions to another registered domain. Image OCR also correlates known-brand login claims with unrelated URLs visible in the screenshot and adds explainable mismatch evidence; it cannot compare pixels to reference pages, identify a page when OCR finds no readable URL, or independently establish that a page is counterfeit. Unavailable RDAP or certificate metadata is reported as unavailable rather than treated as evidence of safety. Certificate-transparency lookups are not implemented.

Known-contact impersonation profiles are private to the account that created them and retain derived writing-style statistics rather than the submitted sample messages. Analysis compares sender identifiers, word overlap, sentence/punctuation/emoji patterns, average word length, casing, and dominant Unicode writing script. At least three non-empty samples are required; insufficient text does not establish identity or authenticity. These deterministic differences are review signals only, are not trained or calibrated identity verification, and can produce false positives when a person changes language, channel, or writing context.

Structured authentication telemetry can learn per-account country, device, and login-hour patterns from successful low-risk events. It stays in a calibration state until three samples exist. If `CYBERGUARD_GEOIP_DB_PATH` points to a licensed local MaxMind GeoLite2 Country database and the `geoip2` dependency is installed, public source IPs are mapped locally to country codes; raw IPs are not persisted by GeoIP enrichment. No GeoIP database is bundled. Network and API analyzers accept structured flow/request records for port scans, volume ratios, regular beacons, and request bursts. Suricata EVE alert records preserve signature ID, category, action, and severity; recognized critical/high/medium/low severity values contribute bounded, deduplicated evidence, with at most three distinct signatures scored per batch. Alerts without a recognized severity are retained as telemetry but do not change risk. Structured network input is scored from its normalized evidence rather than loose keyword matches in serialized field values. This trusts the authenticated sensor's severity labels; it does not validate rule quality or replace signature verification. Bounded PCAP/PCAPNG uploads and the optional `network_sensor.py` process provide IPv4/IPv6 TCP/UDP flow analysis; the live agent aggregates port sets, packet/byte counts, and timestamps before posting authenticated batches. It does not transmit packet payloads, persist a local offline queue, or replace a richer Zeek/Suricata deployment. System-log normalization accepts Windows Event XML/JSON, JSONL, and common Linux syslog lines, then detects selected high-risk event IDs and counted login-failure bursts. These remain explainable rules over submitted telemetry, not a calibrated anomaly model.

The `malware` file-analysis category and EML attachment inspection run the bundled YARA rules when `yara-python` is installed. ZIP files are scanned recursively under fixed resource limits and without extracting files to disk. The rules cover the EICAR test signature, encoded PowerShell and Office AutoOpen/Shell patterns, selected credential-dumping primitives, script download-and-execution combinations, and Run-key persistence. A no-match result is explicitly not a clean bill of health; this is signature triage, not comprehensive malware detection.

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

`evaluate_media_dataset.py --data path\to\untouched\test-media --calibration-data path\to\separate\calibration-media --max-false-positive-rate 0.05 --output media-results.json` selects the highest-recall score threshold independently for each media modality (image, audio, and video) on the separate calibration dataset, then reports overall and per-modality metrics only on the untouched test dataset. Each modality in both roots must contain real and fake samples, and the roots must contain the same modalities; otherwise evaluation stops rather than silently combining unlike detector populations. Both roots must contain nonempty `real/` and `fake/` directories. `--max-false-positive-rate` is a fraction between 0 and 1; if no threshold satisfies the ceiling, evaluation stops with an error instead of quietly choosing one. The output includes each selected cutoff and its calibration metrics; this is decision-threshold selection, not probability calibration and does not automatically configure production scoring. Without `--calibration-data`, `--threshold` uses the caller-supplied cutoff for all modalities and the output labels its source accordingly. Unsupported or undecodable media fails evaluation explicitly rather than contributing a fallback score that could make detector coverage look better than it is.

## Dashboard evidence and forecast limits

The identity-risk panel aggregates risk scores only for masked email addresses observed in incident payloads; it does not infer university roles or identity risk for users without incident evidence. The threat map displays only incidents with caller-reported, range-validated `source_location` metadata and remains empty when no such telemetry exists; the location itself is not independently verified. Media trust inspection uses the image, audio, or sampled-video detector result; its inverse-risk `trust_score` is not a probability and it does not claim voice identity, face identity, or lip-sync verification. The dashboard timeline has an explicit empty state rather than substituting sample counts.

Risk forecasts are linear projections of incident risk averages grouped by observed event hour. They are uncalibrated estimates, expose no confidence percentage, and return insufficient data when there are no incidents. They must not be treated as operational predictions. Insider-risk GET assessments additionally summarize up to 500 of the authenticated user's own CyberGuard audit events from the preceding 30 days; this is not endpoint, file-system, or identity-provider telemetry. Operator-submitted observations remain clearly labelled separately.

Video uploads now sample up to 30 evenly spaced frames for the available image detector and frame-score variance checks. Sampled frames are resized to a maximum 960-pixel edge before retention, and frame sampling is explicitly skipped when metadata or decoded frames exceed the 12-megapixel per-frame bound; audio analysis can still proceed independently. If FFmpeg is installed, the first 10 seconds of the audio stream are separately converted to mono 16 kHz PCM under a 20-second extraction timeout and passed to the audio detector. Missing FFmpeg, timeout, and decode errors are surfaced as explicit audio-analysis statuses; an unavailable audio result does not lower risk or count as an authentic signal.

When audio energy and at least 10 visible-face motion samples are available, a bounded experimental proxy compares short-window audio energy with pixel changes in the lower-face region, searching offsets up to one second. Its correlation and peak offset are review evidence only; it does not change the risk score, establish a mismatch, identify a speaker, or constitute a validated lip-sync detector. This proxy has no representative calibration benchmark yet and must not be used as an authenticity probability.

An authenticated `/api/v1/ws/media` endpoint accepts browser camera frames and explicitly opted-in microphone segments for a five-minute session (up to 300 frames and 60 audio segments). Camera frames are JPEG/PNG/WebP, limited by encoded bytes and pixel dimensions, and rate-limited. Microphone audio is sent as mono PCM16 WAV segments of at most five seconds, limited by sample rate, bytes per segment, aggregate bytes, and request interval. Both are analyzed in worker threads, held in memory only, and not persisted. This remains camera/microphone triage, not integration with a video-call application; live session scores are independent and do not measure synchronization.

The malware rules include a few additional high-signal static indicators (credential-dumping APIs, combined script download/execution patterns, and Run-key persistence); they are triage signatures, not a general-purpose antivirus engine, and a clean result is not proof of safety.

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

## Fresh checkout verification (2026-10-07)

The following checks were run against the current working tree; they supersede historical test counts and claims that dependencies, frontend packages, or media weights are absent:

- Backend: `python -m pytest -q` passed (198 tests, one third-party deprecation warning).
- Frontend: `npm run lint`, `npm run build`, and the authenticated `npm run test:smoke` passed.
- Local application: the API health endpoint and frontend returned HTTP 200; the configured local head-admin login succeeded.
- Pretrained media: `python check_models.py` exercised image and audio inference using the local weight files. A successful inference/load is a runtime smoke check, not an accuracy or calibration result.
- Production deployment: at verification time, the configured Render health URL returned HTTP 404 and the configured Vercel site returned `DEPLOYMENT_NOT_FOUND`. These endpoints therefore do not demonstrate a working production deployment; correct deployment ownership/settings and a redeploy are required.
- Production infrastructure: Docker was unavailable in the verification environment, so PostgreSQL, Redis, worker startup, backup/restore, and production Compose health checks were not run.
- Media evaluation and external actions: no separate authorized media calibration/holdout dataset or live provider credentials were supplied. Pretrained model outputs remain uncalibrated review signals, and external response integrations remain unverified.

These results establish reproducible local checks for the tested paths only. They do not establish 100% implementation coverage, calibrated detector accuracy, production readiness, or a guarantee of zero errors.

### Deployment configuration follow-up (2026-10-07)

- Removed the checked-in production API URL because its Render hostname does not serve this backend. A production Vite build now succeeds only when `VITE_API_URL` is explicitly supplied and rejects a missing value.
- Removed the retired Vercel URL from backend CORS defaults, configured the supplied branch URL in the Render Blueprint, and added the required private Key Value dependency. The Render Blueprint now targets the user-selected free demo, with ephemeral SQLite storage and pretrained media disabled.
- Follow-up local checks: focused backend API tests passed (132 tests), frontend lint passed, and the production frontend build passed with an explicit HTTPS test URL. This URL was only used to verify build configuration and is not a deployment target.
- Live deployment remains unavailable: no Render backend is currently deployed, so the candidate health hostname returns 404; the previously configured Vercel alias also returns 404. Creating the Render Blueprint and setting Vercel's backend URL still require deployment-account access not available in this workspace.
- The supplied branch-specific Vercel URL returns an SSO redirect for anonymous requests. It is not a publicly accessible production origin unless its Deployment Protection setting is changed.

## Implementation gap audit follow-up (2026-10-09)

This snapshot checks the 14-item gap register in `CyberGuard_Implementation_Gap_Audit_Report.pdf` against this checkout. “Implemented locally” means there is code and a passing local check; it does not mean a production integration, representative accuracy, or zero defects has been established.

| Gap | Current status in this checkout | Remaining evidence or dependency |
|---|---|---|
| G-01 Media weights | **Verified locally.** Git LFS objects pass `git lfs fsck`; `check_models.py` loads and runs image and audio inference. | Model hashes and inference still need checking in each deployment image. |
| G-02 Deepfake evaluation | **Workflow implemented; evaluation open.** Separate calibration/test roots, per-modality metrics, and invalid-input checks are implemented. | Authorized, labeled real/fake calibration and untouched test media for image, audio, and video were not supplied. |
| G-03 End-to-end setup | **Local checks pass.** Backend suite, frontend lint/build, model inference, and authenticated browser smoke passed on this Windows checkout. | A clean dependency install on fresh Windows and Linux environments and a deployed browser workflow were not run. |
| G-04 Phishing benchmark | **Workflow implemented; benchmark open.** The bundled UCI benchmark is SMS-only; QR and email analysis paths exist. | Separate licensed email, URL, QR-derived URL, and hard-negative test corpora were not supplied. |
| G-05 Identity calibration | **Feature implemented; calibration open.** Profiles require three samples, are account-scoped, and expose insufficient evidence. | A consented, representative genuine/impersonation corpus and language/channel false-positive evaluation were not supplied. |
| G-06 Response integrations | **Partially implemented.** Jira, ServiceNow, Okta, Microsoft Graph, and EDR adapters are credential-gated; privileged actions require head-admin access, identity/endpoint changes require explicit confirmation, requests have bounded timeouts, and actions use persisted idempotency keys with audit records. Completed duplicates replay the stored response; ambiguous outcomes are blocked for reconciliation. | No provider sandbox credentials were supplied. Provider-specific retry/rollback behavior and live-provider behavior are not established for every adapter. |
| G-07 ATO and identity provider | **Local telemetry path implemented; external validation open.** Account baselines require three successful low-risk samples and scenario tests cover local behavior. | Authorized production IdP/device integration and measured detection delay/false-positive rates were not supplied. |
| G-08 Network visibility | **Bounded local path implemented.** PCAP/PCAPNG, Zeek/Suricata normalization, and the authenticated metadata-only sensor have tests. | Live capture on an authorized sensor host, outage/backpressure testing, and protocol visibility beyond flow metadata remain unverified. |
| G-09 Malware triage | **Bounded signature triage implemented.** EICAR and archive scanning paths are exercised; no-match is reported as no known signature rather than safe. | This is not comprehensive antivirus; broader format coverage and isolated resource-limit testing remain deployment work. |
| G-10 Dashboard evidence | **Partially verified.** Maps and forecasts use observed or explicitly supplied metadata, with empty-data behavior covered in code/tests. | A complete card-by-card trace against a live empty and seeded deployment, including operator filters/time zones, was not recorded. |
| G-11 Production security | **Configuration implemented; deployment open.** Production startup validates required secrets/origins and deployment configuration documents HTTPS, RBAC, CORS, Redis, and secret handling. | No live staging deployment, secret-manager rotation, backup restore, or independent security review was performed. |
| G-12 Load and resilience | **Harness implemented; measurements open.** Locust scenarios are present. | No reproducible load run with hardware, concurrency, latency percentiles, resource use, outage, and restart measurements was recorded. |
| G-13 Privacy and retention | **Partially implemented.** Contact profiles retain derived features, are account-scoped, and can be explicitly deleted; identifiers are masked in selected dashboard summaries. | A complete retention/deletion policy, encryption-at-rest configuration, tenant isolation review, export controls, and consent/access audit remain unverified. |
| G-14 Documentation and evidence | **Partially implemented.** This evaluation, the roadmap acceptance matrix, operations runbook, and release verification script document feature boundaries and local checks. | Deployment evidence and status must be regenerated for each actual release/environment. |

### Current verification result

- Backend: `python -m pytest -q` passed **237 tests** with one third-party deprecation warning.
- Frontend: `npm.cmd run lint` and `npm.cmd run build` passed.
- Browser: authenticated `npm.cmd run test:smoke` passed against a local API and isolated test database.
- Media: `python check_models.py` passed image and audio model inference; `git lfs fsck` passed.
- Async upload handling: image OCR, EML/YARA, PCAP, and media analysis run in worker threads so these CPU/blocking operations do not occupy the API event loop.
- Static diff check: `git -c core.whitespace=cr-at-eol diff --check` passed.

**Overall report closure: not 100%.** Local code paths and checks are stronger, but the missing labeled datasets, consented study data, provider sandbox/live credentials, clean cross-platform install, load/resilience measurements, and staging evidence cannot be manufactured from this checkout. Do not present these gaps as passed or describe detector scores as calibrated probabilities.
