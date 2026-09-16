import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Activity, Atom, AudioLines, Boxes, BrainCircuit, Cable, CircleDot, Code2, Gauge, Globe2, KeyRound, Network, Orbit, Radio, ShieldCheck, Sparkles, Waves, Zap } from 'lucide-react';

const DEMOS = [
  ['chrono-causal', 'Chrono-causal trap', Zap, { exploit_probability: 82, header_jitter: 55, bus_anomaly: 64, route_noise: 30 }],
  ['holographic-memory', 'Holographic memory', Boxes, { pointer_deviation: 74, manifold_distance: 62 }],
  ['hyperbolic-network', 'Hyperbolic network', Network, { nodes: 48, scan_depth: 70 }],
  ['singularity-sinkhole', 'Singularity sinkhole', Orbit, { malicious_stream_score: 88, ack_anomaly: 70, payload_rate: 64 }],
  ['vacuum-keying', 'Vacuum keying', KeyRound, { entropy_bits: 232 }],
  ['software-apoptosis', 'Software apoptosis', ShieldCheck, { debugger_signal: 80, hypervisor_signal: 62, memory_inspection: 72 }],
  ['plasma-channel', 'Plasma channel', AudioLines, { phase_coherence: 84, spectrum_leakage: 18 }],
  ['cognitive-poisoning', 'Cognitive poisoning', BrainCircuit, { perturbation_strength: 60, model_sensitivity: 82 }],
  ['phase-change-zeroization', 'Phase-change storage', Atom, { tamper_signal: 76, voltage_anomaly: 54 }],
  ['photonic-bus', 'Photonic bus', Cable, { probe_signal: 72, polarization_drift: 68 }],
];

export default function SpeculativeDefenseWidget({ apiBaseUrl, accessToken }) {
  const [overview, setOverview] = useState(null);
  const [result, setResult] = useState(null);
  const [threshold, setThreshold] = useState(60);
  const [filter, setFilter] = useState('all');
  const [busy, setBusy] = useState(false);
  const headers = { Authorization: `Bearer ${accessToken}` };
  useEffect(() => { axios.get(`${apiBaseUrl}/api/v1/speculative/overview`, { headers }).then((response) => setOverview(response.data)).catch(() => setOverview(null)); }, [apiBaseUrl, accessToken]);
  const run = async (route, telemetry, label) => { setBusy(true); try { const response = await axios.post(`${apiBaseUrl}/api/v1/speculative/${route}`, { telemetry }, { headers }); setResult({ label, value: response.data }); } finally { setBusy(false); } };
  const visible = DEMOS.filter((item) => filter === 'all' || item[0].includes(filter));
  return <section className="speculative-widget glass-panel p-5 xl:col-span-2" style={{ minHeight: '600px' }}><div className="panel-heading"><div><div className="eyebrow flex items-center gap-2"><Sparkles size={13} /> CYBERGUARD X / SPECULATIVE TELEMETRY</div><h3>Cross-disciplinary defense state space</h3></div><span className="speculative-live"><CircleDot size={12} /> SIMULATED LIVE</span></div><div className="speculative-grid"><div className="speculative-hero"><p>Dynamic threat telemetry metrics for advanced security operations.</p><div className="speculative-metrics"><div><span>Live threat score</span><strong>{overview?.live_threat_score || 0}%</strong></div><div><span>Graph entropy</span><strong>{overview?.graph_entropy || 0}</strong></div><div><span>Autonomous agents</span><strong>{overview?.active_agents || 0}</strong></div><div><span>Defensive counters</span><strong>{overview?.defensive_counters || 0}</strong></div></div><div className="speculative-controls"><label>Risk threshold <strong>{threshold}%</strong><input type="range" min="0" max="100" value={threshold} onChange={(event) => setThreshold(Number(event.target.value))} /></label><label>Vector filter<select value={filter} onChange={(event) => setFilter(event.target.value)}><option value="all">All theoretical vectors</option><option value="memory">Memory</option><option value="network">Network</option><option value="keying">Keying</option><option value="channel">Channel</option></select></label></div></div><div className="speculative-visual"><div className="speculative-ring"><div><Gauge size={25} /><strong>{overview?.telemetry_state || 'pending'}</strong></div></div><span>Telemetry state</span><small>Threshold {threshold}% / counters armed</small></div></div><div className="speculative-actions">{visible.map(([route, label, Icon, telemetry]) => <button key={route} type="button" disabled={busy} onClick={() => run(route, telemetry, label)}><Icon size={16} /><span>{label}</span></button>)}</div>{result && <div className="speculative-result"><div><Radio size={14} /> {result.label}</div><pre>{JSON.stringify(result.value, null, 2)}</pre></div>}<p className="speculative-disclaimer">Simulation-only: no NICs, memory, routes, storage, RF emitters, quantum sensors, photonic buses, or external AI systems are accessed or modified.</p></section>;
}
