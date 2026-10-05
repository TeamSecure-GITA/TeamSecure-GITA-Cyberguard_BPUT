# TeamSecure-GITA-Cyberguard_BPUT

## Local setup and verification

Use Python 3.12 and Node.js compatible with the frontend's Vite version.

1. Create the backend environment and install its development dependencies:

   ```powershell
   cd cyberguard-backend
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements-dev.txt
   Copy-Item .env.example .env
   ```

2. Before starting the API, set `CYBERGUARD_HEAD_ADMIN_USERNAME` and a unique
   `CYBERGUARD_HEAD_ADMIN_PASSWORD` of at least 16 characters in
   `cyberguard-backend\.env`. The API intentionally refuses to start without
   these values. Demo analyst/lead/admin accounts and demo IdP users are only
   created when their respective `CYBERGUARD_DEMO_*_PASSWORD` or
   `CYBERGUARD_IDP_*_PASSWORD` values are explicitly configured. Do not reuse
   passwords from tests or commit `.env`.

   To seed the three demo scenarios, configure the analyst demo password and run
   `python seed_demo_data.py`. Locust requires
   `CYBERGUARD_LOAD_TEST_USERNAME` and `CYBERGUARD_LOAD_TEST_PASSWORD`; use a
   dedicated test account rather than an administrator account.

3. Start the backend from `cyberguard-backend`:

   ```powershell
python -m uvicorn main:app --reload --port 8001
   ```

   Alternatively, start it from the repository root with `npm run backend`.

4. In a second terminal, install and build the frontend:

   ```powershell
   cd cyberguard-frontend
   npm ci
   npm run lint
   npm run build
   # Set these two variables to the admin values configured for the API.
   $env:CYBERGUARD_HEAD_ADMIN_USERNAME = "<configured admin username>"
   $env:CYBERGUARD_HEAD_ADMIN_PASSWORD = "<configured admin password>"
   npm run test:smoke
   ```

5. Run the backend tests from `cyberguard-backend`:

   ```powershell
   python -m pytest -q
   ```

The tests use test-only credentials and an isolated temporary SQLite database.
They do not prove model calibration, live packet capture, external-provider
delivery, or production deployment. The image and audio weights present in
this checkout passed `python check_models.py` with offline loading; each
deployment must still verify that its Git-LFS artifacts were hydrated. Model
inference passing is not calibration evidence, so do not treat heuristic or
uncalibrated output as a production-grade deepfake probability.

Text-model retraining uses a stratified 75/25 split and saves the model trained
only on the 75% training partition, so the reported holdout metrics correspond
to the saved artifact. For example:

```powershell
python train_model.py --data data\uci_sms_spam.csv --output models\threat_text_model.joblib --metrics-output data\uci-sms-training-metrics.json
```

The bundled SMS corpus is not a phishing-email benchmark. Text-model feature
attribution displays local signed TF-IDF/logistic-regression margin
contributions when that compatible model is loaded; terms are redacted when
they resemble addresses, URLs, numbers, or long identifiers. These contributions
are explanatory signals, not causal evidence or calibrated probabilities.

Authorized Zeek or Suricata collectors can submit bounded JSON batches to
`POST /api/v1/network/ingest` using an authenticated session. Supported flow
events are normalized and analyzed; a sufficiently high-risk batch creates an
incident. This ingestion endpoint is not itself a packet sniffer and does not
replace a privileged, continuously running network sensor.

## Future Feature Roadmap (Serially Numbered)

The project is already structured for a SOC dashboard with live detection, AI-assisted triage, and simulated response. The following ideas can be mapped into the current frontend and backend architecture without changing the platform's overall design.

1. **Adversarial self-testing** — `ThreatInspector` + `CyberBrain` on the frontend; `detection_engine.py` + `main.py` on the backend. This feature creates adversarial examples against the model and exposes confidence decay as a live blind-spot map.
2. **Attacker-intent narrative generation** — `CyberBrain` + `ThreatIntelligence` + `XaiModal`; backend via `campaign_engine.py`, `threat_fusion.py`, and `main.py`. This generates plain-language hypotheses for attacker goals and likely next steps.
3. **Attacker fingerprint drift tracking** — `ThreatDNA` + `ThreatGenome` + `ThreatFeed`; backend via `threat_fusion.py`, `campaign_engine.py`, `main.py`. This tracks how attacker TTPs drift over time against your environment.
4. **Defender fatigue-aware alert routing** — `AdminConsole` + `NotificationsPanel` + `IncidentTable`; backend via `main.py`, `forecast_engine.py`, `response_simulator.py`. This routes alerts according to human workload and response capacity.
5. **Simulated breach economics panel** — `RiskGauge` + `ThreatCards` + `ThreatForecast`; backend via `forecast_engine.py` and `main.py`. This converts technical severity into a financial exposure and delay cost view.
6. **Adaptive honeytoken seeding** — `ThreatInspector` + `SecurityFusionCenter`; backend via `main.py` and `detection_engine.py`. This dynamically plants decoy credentials and files based on active attacker probes.
7. **Cross-modal deepfake consistency scoring** — `AdvancedDefenseLab` + `ThreatInspector`; backend via `media_engine.py` and `main.py`. This combines image, audio, video, and metadata timing for a unified authenticity score.
8. **Incident counterfactual replay** — `CyberTimeMachine` + `ThreatIntelligence` + `DigitalTwin`; backend via `digital_twin.py`, `timeline_engine.py`, and `main.py`. This replays a resolved incident with one variable changed to assess what-if scenarios.
9. **Analyst bias detection** — `AdminConsole` + `NotificationsPanel` + `IncidentTable`; backend via `main.py` and audit logging. This flags patterns where analysts escalate or dismiss alerts inconsistently.
10. **Supply-chain blast radius mapping** — `AttackGraph` + `ThreatMap` + `SystemView`; backend via `roadmap_features.py` and `main.py`. This propagates an operator-supplied supplier/dependent graph; it does not discover an organization's inventory.
11. **Living compliance diff** — `ComplianceTab` + `AdminConsole`; backend via `main.py` and compliance logic. This keeps controls up-to-date against new regulations and CVEs.
12. **Threat immune memory** — `ThreatFeed` + `ThreatInspector` + `IncidentTable`; backend via `main.py`, `threat_fusion.py`, `timeline_engine.py`. This stores resolved patterns as memory rules and explains what was caught by memory vs. fresh analysis.
13. **Alert-to-outcome feedback scoring** — `ThreatCards` + `MetricCards` + `AdminConsole`; backend via `main.py`, `detection_engine.py`, and the dashboard metrics layer. This scores whether each alert was correct, noisy, or false and feeds that into the model quality dashboard.
14. **Multi-tenant shared immunity layer** — `AdminConsole` + `SecurityFusionCenter`; backend via `main.py`, `campaign_engine.py`, and `threat_fusion.py`. This allows anonymized, resolved signatures from one tenant to improve security outcomes for others without leaking sensitive details.
15. **Attacker resource-cost estimation** — `ThreatInspector` + `ThreatIntelligence` + `CyberBrain`; backend via `detection_engine.py`, `campaign_engine.py`, `threat_fusion.py`. This estimates whether the attack likely used commodity tooling or a custom, expensive campaign.
16. **Session-level attention heatmap for analysts** — `Header` + `Sidebar` + `ThreatInspector` + `IncidentTable`; backend via `main.py` and event analytics. This visualizes where analysts click and spend time during triage.
17. **Regulatory jurisdiction auto-routing** — `ComplianceTab` + `AdminConsole` + `ThreatIntelligence`; backend via `main.py` and incident metadata processing. This flags which breach-notification rules apply based on jurisdiction and residency signals.
18. **Incident explainability score** — `XaiModal` + `ThreatInspector` + `CyberBrain`; backend via `main.py`, `detection_engine.py`, and `threat_fusion.py`. This displays how traceable and trustworthy the explanation logic is to the analyst.

## Roadmap Acceptance Matrix

The following matrix is the local acceptance baseline for the 18 numbered
roadmap items. “Pass” means the named test exercises the listed behavior in
this repository; it does not claim production calibration, live third-party
delivery, or deployment verification. Rows explicitly marked simulation or
operator-supplied require those boundaries to remain visible in product claims.
The roadmap dashboard uses live authenticated API results, surfaces per-feature
load failures, and does not substitute sample metrics when a request fails.
Honeytoken plans are generated only when requested and remain simulated until a
configured provider deployment is explicitly approved.

| # | Feature / API surface | Local acceptance evidence | Remaining boundary |
|---|---|---|---|
| 1 | Adversarial self-test — `POST /api/v1/adversarial/self-test` | `tests/test_api.py::test_adversarial_self_test_exposes_confidence_decay`; `test_adversarial_self_test_excludes_unchanged_and_duplicate_probes` | Synthetic probes measure score decay; not a robustness certification. |
| 2 | Attacker intent — `GET /api/v1/incidents/{id}/intent` | `tests/test_api.py::test_attacker_intent_uses_shared_ioc_evidence_from_related_incidents` | Hypothesis generation from locally correlated evidence; not verified attribution. |
| 3 | Fingerprint drift — `GET /api/v1/incidents/{id}/drift` | `tests/test_api.py::test_fingerprint_drift_ignores_unrelated_evidence_free_incidents` | Historical repository data only; not a continuously validated actor identity. |
| 4 | Fatigue-aware routing — `POST /api/v1/alert-routing` | `tests/test_api.py::test_defender_fatigue_routing_prioritizes_lightest_load`; `test_fatigue_routing_counts_active_work_and_excludes_resolved_incidents` | Uses current workload and supplied roster; no human-outcome study recorded. |
| 5 | Breach economics — `GET /api/v1/roadmap/economics/{id}` | `tests/test_api.py::test_remaining_roadmap_features_return_safe_operational_artifacts` | Explicit deterministic financial simulation, not a loss forecast. |
| 6 | Honeytoken seeding — `POST /api/v1/roadmap/honeytokens` | `tests/test_api.py::test_remaining_roadmap_features_return_safe_operational_artifacts`; provider deployment tests in `tests/test_provider_integrations.py` | Staging is simulated; real planting requires a configured provider and has not been production-verified. |
| 7 | Cross-modal consistency — `POST /api/v1/roadmap/media-consistency` | `tests/test_api.py::test_cross_modal_consistency_requires_distinct_valid_media_channels`; `test_limited_roadmap_workflows_are_functional` | Depends on media model outputs; scores remain uncalibrated and weights must be verified per deployment. |
| 8 | Counterfactual replay — `POST /api/v1/roadmap/counterfactual/{id}` | `tests/test_api.py::test_limited_roadmap_workflows_are_functional`; `test_counterfactual_replay_rejects_unmodeled_variables_and_actions`; `test_counterfactual_api_returns_validation_errors_for_unmodeled_input` | Bounded deterministic what-if model, not a live environment replay. |
| 9 | Analyst bias — `GET /api/v1/roadmap/bias` | `tests/test_api.py::test_remaining_roadmap_features_return_safe_operational_artifacts` | Heuristic review signals; not a personnel-performance or fairness determination. |
| 10 | Supply-chain blast radius — Supply Chain mode in `AttackGraph`; `POST /api/v1/roadmap/supply-chain` | `tests/test_api.py::test_supply_chain_blast_radius_propagates_only_through_supplied_dependencies`; `test_supply_chain_blast_radius_rejects_unknown_graph_references` | Computes paths only from the operator-supplied inventory and compromise signals; no SBOM/provider discovery. |
| 11 | Living compliance diff — `POST /api/v1/roadmap/compliance-diff` and admin-only `/sync` | `tests/test_api.py::test_limited_roadmap_workflows_are_functional`; `test_synced_cves_persist_and_feed_subsequent_compliance_diffs`; `test_compliance_controls_do_not_claim_unverified_scores` | CVE synchronization needs a configured/reachable feed; outputs require compliance-team review. |
| 12 | Threat immune memory — `GET /api/v1/incidents/{id}/memory` | `tests/test_api.py::test_threat_memory_uses_resolved_history_and_matches_exact_payloads` | Uses resolved local incidents; matching is not proof of common attribution. |
| 13 | Alert-to-outcome feedback — `/api/v1/alert-quality` and `/record` | `tests/test_api.py::test_alert_outcomes_are_persisted_in_configured_database`; `test_sprint_1_intelligence_signals_are_available` | Outcomes inform quality reporting; automatic model retraining is not claimed. |
| 14 | Shared immunity — `/api/v1/roadmap/immunity` and admin-only `/publish` | `tests/test_api.py::test_shared_immunity_signatures_require_evidence_and_hide_metadata`; `test_shared_immunity_publish_uses_configured_installation_identity`; `tests/test_provider_integrations.py::test_tenant_immunity_publish_pseudonymizes_and_filters_payload` | Publishing requires configured tenant/provider credentials; no live tenant exchange was verified. |
| 15 | Attacker resource cost — `GET /api/v1/roadmap/resource/{id}` | `tests/test_api.py::test_remaining_roadmap_features_return_safe_operational_artifacts` | Deterministic estimate from observed text/risk signals; not measured attacker effort. |
| 16 | Analyst attention heatmap — `GET /api/v1/roadmap/attention` | `tests/test_api.py::test_remaining_roadmap_features_return_safe_operational_artifacts` | Aggregates audit events; does not collect or infer unrecorded clicks or time-on-task. |
| 17 | Jurisdiction routing — `GET /api/v1/roadmap/jurisdiction/{id}` | `tests/test_api.py::test_jurisdiction_requires_and_persists_explicit_residency_metadata`; `test_website_analysis_persists_incident_and_jurisdiction_metadata`; `test_uploaded_file_analysis_persists_residency_metadata` | Requires explicit residency metadata; legal counsel must confirm applicable obligations. |
| 18 | Incident explainability — `GET /api/v1/incidents/{id}/explainability` | `tests/test_api.py::test_sprint_1_intelligence_signals_are_available`; `test_trained_text_model_explains_local_linear_features_without_raw_identifiers`; `tests/test_risk_scoring.py::test_legacy_explainability_reports_unavailable_instead_of_synthetic_score` | Linear text-model margins can show local feature contribution; other models and media explanations do not yet have equivalent feature-level attribution. |

## Operations and Deployment

- Dashboard polling refreshes persisted metrics and incident records every ten seconds.
- Incident operators can search, filter, assign, annotate, and move incidents through New, Investigating, Contained, Mitigated, and Closed states.
- MITRE ATT&CK mappings and compliance evidence are available through authenticated APIs.
- `Dockerfile` files and `docker-compose.yml` provide a repeatable deployment path.
- Set `CYBERGUARD_JWT_SECRET`, webhook URLs, and `CYBERGUARD_DB_PATH` through the deployment environment.
- `POST /api/v1/response/execute`
- `POST /api/v1/alert/dispatch`
