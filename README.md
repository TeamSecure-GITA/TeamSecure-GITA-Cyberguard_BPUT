# TeamSecure-GITA-Cyberguard_BPUT

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
10. **Supply-chain blast radius mapping** — `AttackGraph` + `ThreatMap` + `SystemView`; backend via `digital_twin.py`, `campaign_engine.py`, and `main.py`. This models third-party compromise propagation into your environment.
11. **Living compliance diff** — `ComplianceTab` + `AdminConsole`; backend via `main.py` and compliance logic. This keeps controls up-to-date against new regulations and CVEs.
12. **Threat immune memory** — `ThreatFeed` + `ThreatInspector` + `IncidentTable`; backend via `main.py`, `threat_fusion.py`, `timeline_engine.py`. This stores resolved patterns as memory rules and explains what was caught by memory vs. fresh analysis.
13. **Alert-to-outcome feedback scoring** — `ThreatCards` + `MetricCards` + `AdminConsole`; backend via `main.py`, `detection_engine.py`, and the dashboard metrics layer. This scores whether each alert was correct, noisy, or false and feeds that into the model quality dashboard.
14. **Multi-tenant shared immunity layer** — `AdminConsole` + `SecurityFusionCenter`; backend via `main.py`, `campaign_engine.py`, and `threat_fusion.py`. This allows anonymized, resolved signatures from one tenant to improve security outcomes for others without leaking sensitive details.
15. **Attacker resource-cost estimation** — `ThreatInspector` + `ThreatIntelligence` + `CyberBrain`; backend via `detection_engine.py`, `campaign_engine.py`, `threat_fusion.py`. This estimates whether the attack likely used commodity tooling or a custom, expensive campaign.
16. **Session-level attention heatmap for analysts** — `Header` + `Sidebar` + `ThreatInspector` + `IncidentTable`; backend via `main.py` and event analytics. This visualizes where analysts click and spend time during triage.
17. **Regulatory jurisdiction auto-routing** — `ComplianceTab` + `AdminConsole` + `ThreatIntelligence`; backend via `main.py` and incident metadata processing. This flags which breach-notification rules apply based on jurisdiction and residency signals.
18. **Incident explainability score** — `XaiModal` + `ThreatInspector` + `CyberBrain`; backend via `main.py`, `detection_engine.py`, and `threat_fusion.py`. This displays how traceable and trustworthy the explanation logic is to the analyst.

## Operations and Deployment

- Dashboard polling refreshes persisted metrics and incident records every ten seconds.
- Incident operators can search, filter, assign, annotate, and move incidents through New, Investigating, Contained, Mitigated, and Closed states.
- MITRE ATT&CK mappings and compliance evidence are available through authenticated APIs.
- `Dockerfile` files and `docker-compose.yml` provide a repeatable deployment path.
- Set `CYBERGUARD_JWT_SECRET`, webhook URLs, and `CYBERGUARD_DB_PATH` through the deployment environment.
- `POST /api/v1/response/execute`
- `POST /api/v1/alert/dispatch`
