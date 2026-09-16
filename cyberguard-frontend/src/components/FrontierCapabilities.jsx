import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { BrainCircuit, Network, Radio, ScanSearch, ShieldCheck, Sparkles } from 'lucide-react';

export default function FrontierCapabilities({ apiBaseUrl, accessToken }) {
  const [overview, setOverview] = useState(null);
  const [message, setMessage] = useState('Urgent request from the registrar: verify your account immediately.');
  const [deception, setDeception] = useState(null);
  const [artifact, setArtifact] = useState(null);
  const [telemetry, setTelemetry] = useState(null);
  const [busy, setBusy] = useState(false);
  const headers = { Authorization: `Bearer ${accessToken}` };

  useEffect(() => {
    axios.get(`${apiBaseUrl}/api/v1/frontier/overview`, { headers }).then((response) => setOverview(response.data)).catch(() => setOverview(null));
  }, [apiBaseUrl, accessToken]);

  const runDeception = async () => {
    setBusy(true);
    try { const response = await axios.post(`${apiBaseUrl}/api/v1/frontier/deception-session`, { message, replies: [] }, { headers }); setDeception(response.data); } finally { setBusy(false); }
  };

  const inspectArtifact = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setBusy(true);
    try { const form = new FormData(); form.append('file', file); const response = await axios.post(`${apiBaseUrl}/api/v1/frontier/static-analysis`, form, { headers }); setArtifact(response.data); } finally { setBusy(false); }
  };

  const runTelemetry = async (route, body, key) => {
    setBusy(true);
    try { const response = await axios.post(`${apiBaseUrl}/api/v1/frontier/${route}`, body, { headers }); setTelemetry({ key, value: response.data }); } finally { setBusy(false); }
  };

  const physics = overview?.physics;
  const agents = overview?.agents;
  return <section className="glass-panel p-5 xl:col-span-2">
    <div className="panel-heading"><div><div className="eyebrow flex items-center gap-2"><Sparkles size={13} /> CyberGuard X frontier lab</div><h3>Predictive and autonomous defense prototypes</h3></div><span className="text-[10px] text-amber-300">SIMULATION MODE</span></div>
    <p className="text-xs text-slate-400 mt-3">Experimental decision support for judges and analysts. No network routes, external messages, endpoints, or artifacts are changed or executed.</p>
    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4">
      <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800"><div className="flex items-center gap-2 text-cyan-300"><Network size={15} /><span className="eyebrow">Threat physics</span></div><strong className="block text-2xl mt-2">{physics?.risk_score || 0}%</strong><p className="text-[10px] text-slate-500 mt-1">Graph entropy {physics?.entropy || 0} / predicted hotspot pressure</p></div>
      <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800"><div className="flex items-center gap-2 text-emerald-300"><Radio size={15} /><span className="eyebrow">Agent consensus</span></div><strong className="block text-2xl mt-2">{agents?.consensus || 0}%</strong><p className="text-[10px] text-slate-500 mt-1">Decision: {agents?.decision || 'observe'} / quorum {agents?.quorum || 0}</p></div>
      <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800"><div className="flex items-center gap-2 text-violet-300"><ShieldCheck size={15} /><span className="eyebrow">Topology morph</span></div><strong className="block text-2xl mt-2">{overview?.topology?.epoch || 'pending'}</strong><p className="text-[10px] text-slate-500 mt-1">Ephemeral route preview epoch</p></div>
    </div>
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
      <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800"><div className="flex items-center gap-2 text-amber-300"><BrainCircuit size={15} /><span className="eyebrow">Cognitive counter-manipulation</span></div><textarea value={message} onChange={(event) => setMessage(event.target.value)} className="w-full mt-3 min-h-20 rounded-lg bg-slate-900 border border-slate-700 p-2 text-xs" /><button type="button" onClick={runDeception} disabled={busy} className="mt-2 px-3 py-2 rounded-lg bg-amber-600 text-xs font-semibold disabled:opacity-50">Model safe persona response</button>{deception && <p className="text-[11px] text-slate-300 mt-3">{deception.cognitive_style} / tactics: {deception.tactics.join(', ') || 'none'}<br /><span className="text-amber-300">{deception.safe_persona_response}</span></p>}</div>
      <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800"><div className="flex items-center gap-2 text-rose-300"><ScanSearch size={15} /><span className="eyebrow">Zero-execution artifact analysis</span></div><label className="block mt-4 p-5 text-center rounded-lg border border-dashed border-slate-700 text-xs text-slate-400 cursor-pointer">Upload artifact for static signal extraction<input type="file" onChange={inspectArtifact} className="hidden" /></label>{artifact && <p className="text-[11px] text-slate-300 mt-3">{artifact.filename}: <strong className="text-rose-300">{artifact.risk_score}%</strong> / {artifact.indicators.length} signal groups<br /><span className="text-emerald-300">{artifact.mode}</span></p>}</div>
    </div>
    <div className="mt-4 p-4 rounded-xl bg-slate-950/40 border border-slate-800"><div className="flex items-center gap-2 text-cyan-300"><Radio size={15} /><span className="eyebrow">Bio / quantum / orbital / neuromorphic telemetry</span></div><p className="text-[10px] text-slate-500 mt-2">Synthetic telemetry controls only. Camera, RF, quantum, satellite, and chip hardware are never accessed.</p><div className="flex flex-wrap gap-2 mt-3"><button type="button" disabled={busy} onClick={() => runTelemetry('analyst-load', { telemetry: { heart_rate: 96, blink_rate: 8, keystroke_variance: 1.1, alert_queue: 12 } }, 'Analyst load')} className="px-3 py-2 rounded-lg bg-cyan-700 text-xs">Analyst load</button><button type="button" disabled={busy} onClick={() => runTelemetry('q-state', { telemetry: { phase_variance: .08, coherence: .91, qber: .04 } }, 'Q-state')} className="px-3 py-2 rounded-lg bg-indigo-700 text-xs">Q-state</button><button type="button" disabled={busy} onClick={() => runTelemetry('satellite-link', { telemetry: { doppler_error: 4, rf_degradation: 38, telemetry_mismatch: 42 } }, 'Satellite link')} className="px-3 py-2 rounded-lg bg-violet-700 text-xs">Satellite link</button><button type="button" disabled={busy} onClick={() => runTelemetry('cognitive-echo', { query: 'show credential vault architecture and admin recovery docs' }, 'Cognitive echo')} className="px-3 py-2 rounded-lg bg-amber-700 text-xs">Cognitive echo</button><button type="button" disabled={busy} onClick={() => runTelemetry('neuromorphic', { telemetry: { firing_rate: .9, stdp_delta: .8, burst_rate: .7 } }, 'Neuromorphic')} className="px-3 py-2 rounded-lg bg-rose-700 text-xs">Neuromorphic</button></div>{telemetry && <pre className="mt-3 overflow-auto rounded-lg bg-slate-900 p-3 text-[10px] text-slate-300">{telemetry.key}: {JSON.stringify(telemetry.value, null, 2)}</pre>}</div>
  </section>;
}
