import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Activity, BrainCircuit, Crosshair, GitBranch, HeartPulse, Link2, Play, Radar, ShieldCheck, Sparkles, Swords, Waypoints } from 'lucide-react';
import ThreatDNA from './ThreatDNA';
import CampaignCorrelation from './CampaignCorrelation';
import AttackChainTimeline from './AttackChainTimeline';
import RiskForecastGraph from './RiskForecastGraph';
import ResponseSimulatorPanel from './ResponseSimulatorPanel';

const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
const panelClass = 'glass-panel p-5';

function RiskBar({ value, color = 'var(--cyan)' }) {
  return <div className="risk-meter-track"><div className="risk-meter-fill" style={{ width: `${Math.max(0, Math.min(100, value || 0))}%`, background: color }} /></div>;
}

function Panel({ icon: Icon, eyebrow, title, children, action }) {
  return <section className={panelClass}>
    <div className="panel-heading">
      <div><div className="eyebrow flex items-center gap-2"><Icon size={13} />{eyebrow}</div><h3>{title}</h3></div>
      {action}
    </div>
    <div className="pt-4">{children}</div>
  </section>;
}

export default function ThreatIntelligence({ accessToken, incidents = [] }) {
  const [selectedId, setSelectedId] = useState(incidents[0]?.database_id || null);
  const [genome, setGenome] = useState(null);
  const [correlations, setCorrelations] = useState(null);
  const [timeline, setTimeline] = useState(null);
  const [forecast, setForecast] = useState(null);
  const [twin, setTwin] = useState(null);
  const [psychology, setPsychology] = useState(null);
  const [healing, setHealing] = useState(null);
  const [battle, setBattle] = useState(null);
  const [selectedActions, setSelectedActions] = useState(['isolate', 'revoke']);
  const [busy, setBusy] = useState(false);
  const config = { headers: { Authorization: `Bearer ${accessToken}` } };
  const selectedIncident = incidents.find((incident) => incident.database_id === selectedId) || incidents[0];

  useEffect(() => {
    if (!selectedId && incidents[0]?.database_id) setSelectedId(incidents[0].database_id);
  }, [incidents, selectedId]);

  useEffect(() => {
    if (!selectedIncident?.database_id) return;
    const id = selectedIncident.database_id;
    Promise.all([
      axios.get(`${apiBaseUrl}/api/v1/incidents/${id}/dna`, config),
      axios.get(`${apiBaseUrl}/api/v1/incidents/${id}/correlations`, config),
      axios.get(`${apiBaseUrl}/api/v1/incidents/${id}/attack-chain`, config),
      axios.post(`${apiBaseUrl}/api/v1/psychology/analyze`, { payload: selectedIncident.explanation || selectedIncident.category }, config),
      axios.get(`${apiBaseUrl}/api/v1/network/twin`, config),
      axios.post(`${apiBaseUrl}/api/v1/forecast`, { horizon: 6 }, config),
      axios.post(`${apiBaseUrl}/api/v1/self-heal`, { incident_id: id }, config),
    ]).then(([genomeResponse, correlationResponse, timelineResponse, psychologyResponse, twinResponse, forecastResponse, healingResponse]) => {
      setGenome(genomeResponse.data.genome);
      setCorrelations(correlationResponse.data);
      setTimeline(timelineResponse.data.events);
      setPsychology(psychologyResponse.data);
      setTwin(twinResponse.data);
      setForecast(forecastResponse.data);
      setHealing(healingResponse.data);
    }).catch(() => {});
  }, [selectedIncident?.database_id, accessToken]);

  const runBattle = async () => {
    setBusy(true);
    try {
      const battleResponse = await axios.post(`${apiBaseUrl}/api/v1/battle`, { defender_actions: selectedActions }, config);
      setBattle(battleResponse.data);
    } finally {
      setBusy(false);
    }
  };

  return <div className="space-y-5">
    <div className="page-heading">
      <div><div className="eyebrow"><span className="live-pulse" /> CyberGuard X / intelligence layer</div><h2>Threat Intelligence <span>operating picture</span></h2></div>
      <select className="intel-select" value={selectedIncident?.database_id || ''} onChange={(event) => setSelectedId(Number(event.target.value))}>
        {incidents.length ? incidents.map((incident) => <option key={incident.database_id} value={incident.database_id}>{incident.id} · {incident.category}</option>) : <option value="">Waiting for incidents</option>}
      </select>
    </div>

    <div className="intel-kpi-grid">
      <div className={panelClass}><span className="eyebrow">Threat genome</span><strong className="intel-kpi-value">{genome?.fingerprint || '--------'}</strong><span className="intel-kpi-note">Fingerprint / {genome?.similarity_score || 0}% similarity</span></div>
      <div className={panelClass}><span className="eyebrow">Campaign confidence</span><strong className="intel-kpi-value">{correlations?.confidence || 0}%</strong><span className="intel-kpi-note">{correlations?.campaign_id || 'No campaign yet'}</span></div>
      <div className={panelClass}><span className="eyebrow">Future risk</span><strong className="intel-kpi-value">{forecast?.forecast?.[forecast.forecast.length - 1]?.risk || 0}%</strong><span className="intel-kpi-note">{forecast?.trend || 'stable'} / next 6 hours</span></div>
      <div className={panelClass}><span className="eyebrow">Manipulation score</span><strong className="intel-kpi-value">{psychology?.manipulation_score || 0}%</strong><span className="intel-kpi-note">{psychology?.risk_level || 'Unknown'} social engineering risk</span></div>
    </div>

    <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
      <Panel icon={BrainCircuit} eyebrow="01 / threat DNA" title="Genome fingerprint">
        <ThreatDNA genome={genome} incidentId={selectedIncident?.database_id} />
      </Panel>
      <Panel icon={Link2} eyebrow="02 / shadow campaign" title="Cross-incident correlation">
        <CampaignCorrelation correlations={correlations} />
      </Panel>
      <Panel icon={GitBranch} eyebrow="03 / cyber time machine" title="Attack chain timeline">
        <AttackChainTimeline timeline={timeline} />
      </Panel>
      <Panel icon={Activity} eyebrow="04 / future threat predictor" title="Risk forecast">
        <RiskForecastGraph forecast={forecast} />
      </Panel>
      <Panel icon={Waypoints} eyebrow="05 / digital twin" title="Live network propagation">
        <div className="twin-map">{(twin?.nodes || []).map((node, index) => <div className={`twin-node twin-${node.kind}`} style={{ left: `${12 + (index % 3) * 34}%`, top: `${20 + Math.floor(index / 3) * 32}%` }} key={node.id}><span>{node.kind === 'threat' ? <Crosshair size={13} /> : <Radar size={13} />}</span><small>{node.label}</small></div>)}</div>
        <div className="twin-footer"><span>{twin?.nodes?.length || 0} nodes observed</span><span className="text-emerald-300">● live telemetry</span></div>
      </Panel>
      <Panel icon={Sparkles} eyebrow="06 / human manipulation" title="Psychology signal map">
        <div className="risk-meter-label"><span>Manipulation pressure</span><strong>{psychology?.manipulation_score || 0}%</strong></div><RiskBar value={psychology?.manipulation_score} color="#f6c76c" />
        <div className="psychology-grid">{(psychology?.tactics || []).map((tactic) => <div className={tactic.detected ? 'psychology-hit' : ''} key={tactic.name}><span>{tactic.name}</span><b>{tactic.detected ? 'detected' : 'clear'}</b></div>)}</div>
      </Panel>
      <Panel icon={ShieldCheck} eyebrow="07 / self-healing network" title="Recovery sequence">
        <div className="healing-header"><strong>{healing?.priority || 'normal'} priority</strong><span>{healing?.estimated_recovery_minutes || 0} min estimate</span></div>
        <div className="intel-list">{(healing?.actions || []).map((action) => <div className="intel-row" key={action.order}><span>{String(action.order).padStart(2, '0')}</span><small>{action.label}</small><b>ready</b></div>)}</div>
      </Panel>
      <Panel icon={Swords} eyebrow="08 / AI defender vs attacker" title="Battle arena" action={<button className="icon-action" title="Run battle simulation" onClick={runBattle} disabled={busy}><Play size={14} /></button>}>
        <div className="action-chips">{[['isolate', 'Isolate'], ['revoke', 'Revoke'], ['block', 'Block'], ['notify', 'Notify']].map(([id, label]) => <button className={selectedActions.includes(id) ? 'action-chip active' : 'action-chip'} key={id} onClick={() => setSelectedActions((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id])}>{label}</button>)}</div>
        <div className="battle-result">{battle ? <><strong>{battle.winner === 'defender' ? 'DEFENDER ADVANTAGE' : 'ATTACKER PRESSURE'}</strong><span>Surviving risk {battle.surviving_risk}% · {battle.rounds.length} rounds modeled</span></> : <span>Choose controls, then run the live scenario.</span>}</div>
      </Panel>
      <Panel icon={HeartPulse} eyebrow="09 / what-if simulator" title="Projected response impact">
        <ResponseSimulatorPanel incident={selectedIncident} accessToken={accessToken} apiBaseUrl={apiBaseUrl} />
      </Panel>
    </div>

    <div className={panelClass}><div className="eyebrow flex items-center gap-2"><BrainCircuit size={13} /> 10 / cyber brain XAI</div><div className="brain-strip"><strong>{selectedIncident?.id || 'No incident selected'}</strong><span>{selectedIncident?.explanation || 'The explainable reasoning layer will appear after the first analyzed incident.'}</span><span className="brain-status">MODEL EVIDENCE LINKED</span></div></div>
  </div>;
}

