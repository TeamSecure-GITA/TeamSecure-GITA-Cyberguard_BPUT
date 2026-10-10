# CyberGuard audit closure matrix

Updated 10 October 2026 against the 16-gap audit supplied in this chat. This tracks repository implementation and local evidence. It does not certify real-world detection quality, security, or a live deployment.

## Revalidation on 10 October 2026

The current checkout was revalidated after the audit report was supplied. The media artifact concern from that report does not reproduce in this checkout: the configured image and audio weight files are binary files (approximately 343 MB and 378 MB), not Git-LFS pointer text, and `python check_models.py` completed image and audio inference successfully. This proves the present local artifacts can load and execute; it does not establish model accuracy, licensing, clean-machine download reproducibility, or production suitability. Keep G3 and the dataset/calibration gate open until authorized, source-tracked calibration and untouched test sets are available.

Recorded local results:

- `python -m pytest -p no:cacheprovider --basetemp=.pytest-tmp-user-audit -q`: **241 passed**, one upstream Starlette/AnyIO deprecation warning.
- `python check_models.py`: **PASS** for image and audio inference using the checked-out weight files.
- `npm.cmd run lint`: **PASS**.
- `$env:VITE_API_URL='https://build-validation.invalid'; npm.cmd run build`: **PASS**. The URL is build-only and is not a deployment check.
- After the signed YARA updater change, `python -m pytest -p no:cacheprovider --basetemp=.pytest-tmp-final-closure -q`: **245 passed**, one upstream Starlette/AnyIO deprecation warning.
- G9 focused regressions: `python -m pytest -p no:cacheprovider --basetemp=.pytest-tmp-yara-update -q tests/test_yara_updates.py tests/test_api.py -k 'yara or malware_scanner'`: **14 passed**.
- `docker --version` was unavailable in this environment; PostgreSQL/Redis compose startup and recovery drills could not be performed here.

These results are local evidence only. Provider-side actions, public staging, representative datasets, live PostgreSQL/Redis recovery, and measured load/security review still require their respective external environments and evidence.

| Gap | Status in this checkout | Implementation and remaining acceptance evidence |
|---|---|---|
| G1 Browser smoke | **Passed locally** | `cyberguard-frontend/tests/smoke.mjs` now uses labeled login controls, checks the rejected and accepted HTTP responses, and asserts the actual dashboard heading. Login errors expose an alert role. The authenticated smoke passed on a local API and isolated database. |
| G2 Deployment health and authenticated smoke | **Release gate implemented; deployment unverified** | `verify_all.ps1 -RequireDeploymentChecks` fails when `API_URL` or `CYBERGUARD_FRONTEND_URL` is missing and runs health plus authenticated browser checks when configured. No working staging/public deployment URL and release credentials were supplied here. |
| G3 Media score calibration | **Score claims corrected; empirical calibration open** | Media metrics no longer treat raw anomaly scores as probabilities. The evaluator reports per-modality confusion matrix, ROC-AUC, PR-AUC, FPR, latency, and can select thresholds from separate calibration data. UI labels media risk as a `/99` triage score. Authorized calibration and untouched test media are still required before making accuracy or probability claims. |
| G4 Text benchmark coverage | **Evaluation workflow added; representative benchmark open** | `evaluate_public_datasets.py` supports separate train/calibration/test manifests and per-category models/metrics, selects thresholds only on calibration data, records source/license metadata, and rejects normalized exact-text duplicates across splits. Licensed email, URL, QR, social, and hard-negative corpora were not supplied; near-duplicate review remains manual. |
| G5 Provider enforcement | **Mocked/local paths covered; live behavior unverified** | Provider adapters are credential-gated and have timeout, idempotency, authorization, audit, and failure tests. No provider sandbox credentials were supplied, so provider-specific success, retry, rollback, and confirmed enforcement remain unverified. |
| G6 Live/temporal deepfake | **Capability explicitly scoped** | Uploads use image/audio models and sampled video frames; the live browser session is camera/microphone triage. UI and `EVALUATION.md` state that it does not integrate with a video-call app or verify identity/lip-sync. A validated temporal detector requires authorized evaluation data and is not claimed. |
| G7 Contact impersonation | **Privacy controls improved; calibration open** | Creating a profile now requires explicit consent. Derived features are stored instead of sample messages; profiles are account-scoped, deletable, and expire on list after `CYBERGUARD_KNOWN_CONTACT_RETENTION_DAYS` (default 90). Tests cover consent, expiry, ownership, and short-message insufficiency. Representative consented language/channel evaluation remains unavailable. |
| G8 Network coverage | **Bounded local telemetry tested; live capture open** | Zeek/Suricata normalization, IPv4/IPv6 flow extraction, PCAP limits, and metadata-only sensor paths are covered by tests and documented. Authorized sensor-host capture, packet-loss/backpressure behavior, and richer protocol inspection were not exercised. |
| G9 Malware triage | **Bounded scan and signed update path; isolation/update operations open** | YARA match calls have a configurable 1–60 second timeout; timeout/error outcomes are explicit and never reported as clean. ZIP-member scanning is bounded. `update_yara_rules.py` verifies an Ed25519 signature and SHA-256, compiles candidate rules, and atomically replaces the active file. A constrained worker process, broader file-format coverage, and production signing-key provisioning/update drills remain open. This remains signature triage. |
| G10 External enrichment | **Unavailable states and provider provenance implemented; live status open** | RDAP and CT integrations have guarded requests, provider/source status, limits, and mocked tests. Live provider freshness, DNS/TLS outage behavior, and rate-limit handling require external network verification. |
| G11 Cross-category risk comparability | **Evidence accounting tested; calibration open** | Risk attribution conserves the detector score and category-specific actions/thresholds have regression coverage. Scores remain heuristic and are not calibrated to comparable probabilities across categories; category-specific cost/threshold review requires labeled validation data. |
| G12 Privacy and tenant isolation | **Selected controls tested; full review open** | Contact profiles and multiple API resources are owner-scoped and tested; deletion, consent, retention, and audit behavior exist for contact profiles. A full adversarial review of all tenants/resources, export controls, organization-wide retention, encryption-at-rest, and secret redaction remains outstanding. |
| G13 PostgreSQL/Redis/recovery | **Configuration and unit workflows present; live recovery unverified** | Compose, database adapter, Redis state tests, and SQLite backup tests exist. Docker is unavailable in this workspace, so PostgreSQL migration, Redis outage/restart, and PostgreSQL backup/restore were not run against live services. |
| G14 Maps and forecasts | **Evidence limits implemented** | Identity aggregation uses observed identifiers, maps require caller-reported valid coordinates, and forecasts expose insufficient-data/uncalibrated states. A live card-by-card empty/seeded dashboard review was not recorded. |
| G15 Certificate Transparency | **Locally implemented and mocked-tested** | CT behavior is controlled by `CYBERGUARD_ENABLE_CT`, reports disabled/unavailable separately, and has deterministic provider tests. A live provider check and status reconciliation against a deployed runtime remain outstanding. |
| G16 Performance/scalability | **Harness present; measurements open** | Locust workloads exist. No repeatable run with hardware, concurrency, latency percentiles, error rates, resource use, and failure/restart measurements was supplied or recorded. |

### G9 local improvement

YARA matching now has a bounded per-match timeout, configurable with `CYBERGUARD_YARA_TIMEOUT_SECONDS` (default 10 seconds, clamped to 1–60). Timeout and scanner errors are returned as incomplete outcomes and never as clean/no-match. ZIP entry/member/aggregate/depth limits continue to apply. This reduces runaway scan time but is not process or container isolation and does not broaden supported archive formats.

Signed rule updates are now supported through `cyberguard-backend/update_yara_rules.py`. The updater accepts only a two-file ZIP bundle, checks size and checksum, verifies an Ed25519 signature using an operator-provisioned PEM public key, compiles the proposed rules before changing the active file, and then uses an atomic replacement. It does not fetch bundles or create signing keys. The operator must distribute the trusted public key securely and protect the corresponding private signing key. A production signing-key rotation drill and isolated scanner worker are still open.

## Local verification

- Backend suite: `python -m pytest -p no:cacheprovider --basetemp=.pytest-tmp-audit-final -q` (see current run result in the verification notes below).
- Frontend: `npm.cmd run lint` and `VITE_API_URL=https://build-validation.invalid npm.cmd run build` passed; the URL is a build-only placeholder, not a deployment.
- Browser: `npm.cmd run test:smoke` passed against a local API, isolated temporary database, and temporary administrator account.
- The pre-existing working-tree change to `cyberguard-backend/cyberguard.db` was not modified as part of this work.

## Closure boundary

“100% implemented” cannot be established from source code alone. This checkout still needs representative licensed datasets, provider sandbox access, working deployment endpoints, production database/cache recovery drills, load measurements, and an independent security review. Do not describe risk scores as calibrated probabilities or claim that provider actions were executed unless the provider confirms success.
