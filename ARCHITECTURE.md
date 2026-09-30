# CYBERGUARD Architecture

## Data Flow

```mermaid
flowchart LR
  UI[React SOC Dashboard] -->|Bearer token / WebSocket| API[FastAPI API]
  API --> AUTH[JWT sessions, RBAC, passkeys]
  API --> ROUTER[Analysis and incident orchestration]
  ROUTER --> ENGINE[Hybrid detection engine]
  ENGINE --> RULES[Text, URL, identity, auth and telemetry rules]
  ENGINE --> TEXT[TF-IDF classifier and optional transformer]
  ENGINE --> MEDIA[Image, audio and sampled-video analysis]
  ROUTER --> INTEL[IOC, email-auth and website enrichment]
  API --> DB[(SQLite development / PostgreSQL production)]
  API --> REDIS[(Redis ephemeral state in production)]
  API --> ACTIONS[Approved response and provider integrations]
  API --> UI
```

## Detection Sources

- Email, SMS, social messages, URLs, and impersonation text use explainable rules plus available trained text-model signals. EML analysis checks sender-authentication evidence; URL submissions receive lexical and brand-lookalike analysis.
- Brand lookalike domains are loaded from `cyberguard-backend/data/brand_domains.json`; set `CYBERGUARD_BRAND_DOMAINS_FILE` to an alternate JSON file to extend or replace the trusted-brand list.
- Image and audio uploads use byte-level anomaly features and optional pretrained model adapters. Videos are sampled into frames for image analysis; this is not live-call, temporal, or lip-sync detection. Missing pretrained weights cause fallback behavior and are reported by the model-status endpoint.
- Authentication submissions use one shared ATO/auth-log scoring path. System, network, API, malware, and exfiltration submissions currently use structured text/signature analysis; the API does not capture packets or scan uploaded files with YARA.
- Authentication telemetry can build a per-account country/device/hour baseline from at least three explicitly successful, low-risk events. Device identifiers are hashed and raw IPs are not stored. Optional country lookup uses a local MaxMind database configured with `CYBERGUARD_GEOIP_DB_PATH`; without that file, caller-provided country data is only a hint.
- Network/API JSON submissions can be analyzed as normalized flow and request records for broad port probing, outbound-volume anomalies, regular beacon intervals, request-rate bursts, and rate-limit responses. System logs accept event JSON, newline-delimited JSON, Windows Event XML, and common Linux syslog lines; selected event IDs and patterns cover audit-log clearing, privileged account changes, service/task installation, and failed-login bursts. This does not provide packet capture, full PCAP parsing, or a learned network model. File uploads in the `malware` category are checked against bundled YARA rules when `yara-python` is available; bundled signatures are intentionally narrow and do not replace endpoint antivirus.
- Website inspection performs SSRF-safe live fetching, reports verified TLS issuer/validity/age metadata, and checks redirect chains and credential forms. DOM brand claims and cross-domain password-form submissions add impersonation evidence. RDAP registration-age lookup is available when `CYBERGUARD_ENABLE_RDAP=true` and safely validates public redirect targets; it is disabled by default. Certificate transparency and screenshot-based visual similarity are not implemented.
- EML analysis scans the message body and bounded text attachments, hashes attachment bytes, and flags potentially active file extensions. It does not unpack archives, execute files, inspect document macros, or replace antivirus/YARA scanning.

## Security Controls

- Login creates a signed JWT. Set `CYBERGUARD_JWT_SECRET` to a long secret outside development.
- Anonymous API evaluation is disabled by default. Set `CYBERGUARD_ALLOW_ANONYMOUS_EVAL=false` in every deployed environment.
- The application firewall records suspicious probes and can block repeat offenders; Cloudflare enforcement requires both `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ZONE_ID`.
- Security email notifications require the `CYBERGUARD_SMTP_*` settings. Notifications are alerts, not an approval gate.
- Workspace access uses `POST /api/v1/access/request`, an owner approval link, and `GET /api/v1/access/status`; set `CYBERGUARD_PUBLIC_APP_URL` to the deployed frontend URL so approval links point to the correct environment.
- React code delivered to a browser cannot be made invisible to that browser's developer tools. Keep secrets, detection rules, and privileged operations on the backend.
- Analyst users can inspect and create incidents.
- Lead users can execute response actions.
- SQLite is used for development; production Compose configures PostgreSQL. Redis is used for shared expiring authentication state in production.
- External actions require provider configuration and explicit authorization; integrations are not implied to be live merely because a recommendation is shown.

## Main API Routes

- `POST /api/v1/auth/login`
- `POST /api/v1/access/request`
- `GET /api/v1/access/status`
- `GET /api/v1/access/approve`
- `POST /api/v1/analyze`
- `POST /api/v1/analyze/file`
- `GET /api/v1/incidents`
- `GET /api/v1/dashboard/metrics`
- `GET /api/v1/dashboard/timeline`
- `GET /api/v1/dashboard/graph`
- `GET /api/v1/system/health`
- `GET /api/v1/models/status`
- `GET /api/v1/compliance/controls`
- `GET /api/v1/compliance/mitre`
- `GET /api/v1/integrations/status`
- `POST /api/v1/integrations/siem/ingest`
- `PATCH /api/v1/incidents/{id}`
- `POST /api/v1/incidents/{id}/comments`
- `GET /api/v1/events/recent`
- `GET /api/v1/notifications`
- `PATCH /api/v1/notifications/{id}`
- `GET /api/v1/incidents/{id}`
- `POST /api/v1/threat-intel/lookup`
- `GET /api/v1/admin/users`
- `POST /api/v1/admin/users`
- `GET /api/v1/admin/audit`

## Future Feature Roadmap (Serially Numbered)

This roadmap captures the advanced SOC feature ideas discussed for CyberGuard and maps them to the current architecture. Each item indicates the likely frontend surface, backend service, and integration point in the existing stack.

### 1. Adversarial self-testing
- Frontend: `ThreatInspector`, `ThreatIntelligence`, `CyberBrain`
- Backend: `detection_engine.py`, `main.py`
- Purpose: generate adversarial probes against the model and visualize confidence decay across blind spots.

### 2. Attacker-intent narrative generation
- Frontend: `CyberBrain`, `ThreatIntelligence`, `XaiModal`
- Backend: `main.py`, `campaign_engine.py`, `threat_fusion.py`
- Purpose: produce plain-language attacker goal hypotheses and next-move explanations.

### 3. Attacker fingerprint drift tracking
- Frontend: `ThreatDNA`, `ThreatGenome`, `ThreatFeed`
- Backend: `threat_fusion.py`, `campaign_engine.py`, `main.py`
- Purpose: track TTP drift and campaign evolution across incidents over time.

### 4. Defender fatigue-aware alert routing
- Frontend: `AdminConsole`, `NotificationsPanel`, `IncidentTable`
- Backend: `main.py`, `forecast_engine.py`, `response_simulator.py`
- Purpose: route alerts based on analyst load, burnout risk, and response capacity.

### 5. Simulated breach economics panel
- Frontend: `RiskGauge`, `ThreatCards`, `ThreatForecast`
- Backend: `forecast_engine.py`, `main.py`
- Purpose: convert technical severity into financial exposure and delay cost.

### 6. Adaptive honeytoken seeding
- Frontend: `ThreatInspector`, `SecurityFusionCenter`
- Backend: `main.py`, `detection_engine.py`
- Purpose: plant fake credentials and files in response to ongoing reconnaissance behavior.

### 7. Cross-modal deepfake consistency scoring
- Frontend: `AdvancedDefenseLab`, `ThreatInspector`
- Backend: `media_engine.py`, `main.py`
- Purpose: combine audio, image, video, and metadata consistency signals into one authenticity score.

### 8. Incident counterfactual replay
- Frontend: `CyberTimeMachine`, `ThreatIntelligence`, `DigitalTwin`
- Backend: `digital_twin.py`, `timeline_engine.py`, `main.py`
- Purpose: replay incident conditions with one variable changed to evaluate alternate outcomes.

### 9. Analyst bias detection
- Frontend: `AdminConsole`, `NotificationsPanel`, `IncidentTable`
- Backend: `main.py`, `audit/event logging`, `response_simulator.py`
- Purpose: detect alert-dismissal, escalation, and decision patterns by analyst over time.

### 10. Supply-chain blast radius mapping
- Frontend: `AttackGraph`, `ThreatMap`, `SystemView`
- Backend: `digital_twin.py`, `campaign_engine.py`, `main.py`
- Purpose: model vendor and third-party exposure propagation into the environment.

### 11. Living compliance diff
- Frontend: `ComplianceTab`, `AdminConsole`
- Backend: `main.py`, `compliance controls services`
- Purpose: auto-diff applied controls and detected gaps against new regulations and CVEs.

### 12. Threat immune memory
- Frontend: `ThreatFeed`, `ThreatInspector`, `IncidentTable`
- Backend: `main.py`, `threat_fusion.py`, `timeline_engine.py`
- Purpose: compress resolved incidents into memory rules and show what was caught by memory vs. fresh analysis.

### 13. Alert-to-outcome feedback scoring
- Frontend: `ThreatCards`, `MetricCards`, `AdminConsole`
- Backend: `main.py`, `detection_engine.py`, `dashboard metrics`
- Purpose: track whether a detection was right, wrong, or noisy and feed outcome quality back into the model accuracy dashboard.

### 14. Multi-tenant shared immunity layer
- Frontend: `AdminConsole`, `SecurityFusionCenter`
- Backend: `main.py`, `campaign_engine.py`, `threat_fusion.py`
- Purpose: anonymized resolved signatures from one tenant can improve detection for all tenants without leaking sensitive data.

### 15. Attacker resource-cost estimation
- Frontend: `ThreatInspector`, `ThreatIntelligence`, `CyberBrain`
- Backend: `detection_engine.py`, `campaign_engine.py`, `threat_fusion.py`
- Purpose: judge whether the attack appears low-sophistication commodity tooling or a custom, costlier campaign.

### 16. Session-level attention heatmap for analysts
- Frontend: `Header`, `Sidebar`, `ThreatInspector`, `IncidentTable`
- Backend: `main.py`, `audit logging`, `analytics events`
- Purpose: analyze where analysts click, spend time, and route decisions to optimize UI design around real SOC behavior.

### 17. Regulatory jurisdiction auto-routing
- Frontend: `ComplianceTab`, `AdminConsole`, `ThreatIntelligence`
- Backend: `main.py`, `compliance controls`, `incident metadata processing`
- Purpose: infer applicable breach-notification rules such as GDPR or DPDP based on data residency and cross-border signals.

### 18. Incident explainability score
- Frontend: `XaiModal`, `ThreatInspector`, `CyberBrain`
- Backend: `main.py`, `detection_engine.py`, `threat_fusion.py`
- Purpose: show how traceable and trustworthy the explanation is, and whether analysts should rely on it or verify manually.

## Frontend Development Priorities

- Core SOC workbench: `App`, `Sidebar`, `Header`, `MetricCards`, `IncidentTable`, `ThreatFeed`
- Threat intelligence panels: `ThreatIntelligence`, `ThreatDNA`, `ThreatGenome`, `CampaignCorrelation`
- Detection workflow: `ThreatInspector`, `TrustScanner`, `IocReputationFeed`
- Simulation layer: `FrontierCapabilities`, `AdvancedDefenseLab`, `SpeculativeDefenseWidget`, `ResponseSimulatorPanel`
- Governance and operations: `ComplianceTab`, `AdminConsole`, `NotificationsPanel`

## Backend Development Priorities

- Detection core: `detection_engine.py`, `extended_intel.py`, `threat_intel.py`
- Context and correlation: `campaign_engine.py`, `threat_fusion.py`, `digital_twin.py`, `timeline_engine.py`
- Forecasting and response: `forecast_engine.py`, `response_simulator.py`, `self_healing.py`, `battle_simulator.py`
- AI safety and simulation: `frontier_engine.py`, `advanced_defense_engine.py`, `speculative_defense_engine.py`
- API orchestration: `main.py`

## Operations and Deployment

- Dashboard polling refreshes persisted metrics and incident records every ten seconds.
- Incident operators can search, filter, assign, annotate, and move incidents through New, Investigating, Contained, Mitigated, and Closed states.
- MITRE ATT&CK mappings and compliance evidence are available through authenticated APIs.
- `Dockerfile` files and `docker-compose.yml` provide a repeatable deployment path.
- Set `CYBERGUARD_JWT_SECRET`, webhook URLs, and `CYBERGUARD_DB_PATH` through the deployment environment.
- `POST /api/v1/response/execute`
- `POST /api/v1/alert/dispatch`
