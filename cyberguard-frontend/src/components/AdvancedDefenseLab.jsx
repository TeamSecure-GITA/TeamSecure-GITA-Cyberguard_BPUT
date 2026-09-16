import React, { useState } from 'react';
import axios from 'axios';
import { Activity, AudioLines, BrainCircuit, Cable, Clock3, Code2, KeyRound, Network, Orbit, ShieldCheck, Sparkles, Waves, Zap } from 'lucide-react';

const DEMOS = [
  ['heartbeat-keying', 'Heartbeat keying', KeyRound, { telemetry: { heart_rate: 74, hrv: .56, micro_tremor: .08, presence_confidence: .96 } }],
  ['quantum-decoy', 'Quantum decoy', Orbit, { probe: 'credential-service', tool: 'scanner-probe' }],
  ['temporal-healing', 'Temporal healing', Clock3, { state: { corrupted_blocks: 4, unauthorized_cycles: 8 } }],
  ['acoustic-channel', 'Acoustic channel', AudioLines, { telemetry: { ultrasonic_energy: 72, modulation_confidence: 65, fan_pwm_variance: 44 } }],
  ['polymorphism', 'Ghost compilation', Code2, { binary: { function_count: 840, layout_entropy: .74 } }],
  ['infrastructure-echo', 'Infrastructure echo', BrainCircuit, { query: 'credential vault admin API topology' }],
  ['dark-mesh', 'Dark compute mesh', Network, { nodes: ['gateway', 'identity', 'payments', 'soc'], epoch: 7 }],
  ['vaccine-recommendations', 'Threat vaccines', ShieldCheck, { indicators: ['suspicious-login.xyz', 'credential-replay'] }],
  ['space-weather', 'Space weather', Waves, { telemetry: { solar_activity: 78, bit_flip_rate: 22, link_loss: 35 } }],
  ['counter-agent', 'Counter-agent triage', Zap, { telemetry: { voice_deepfake_score: 88, video_deepfake_score: 81 } }],
];

export default function AdvancedDefenseLab({ apiBaseUrl, accessToken }) {
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const headers = { Authorization: `Bearer ${accessToken}` };
  const run = async (route, body, label) => {
    setBusy(true);
    try { const response = await axios.post(`${apiBaseUrl}/api/v1/advanced/${route}`, body, { headers }); setResult({ label, value: response.data }); } finally { setBusy(false); }
  };
  return <section className="glass-panel p-5 xl:col-span-2"><div className="panel-heading"><div><div className="eyebrow flex items-center gap-2"><Sparkles size={13} /> Advanced Defense Lab</div><h3>Experimental protection simulations</h3></div><span className="text-[10px] text-amber-300">PREVIEW ONLY</span></div><p className="text-xs text-slate-400 mt-3">Synthetic telemetry and decision support. No biometric sensors, quantum hardware, RF systems, process memory, routes, binaries, meetings, or external actors are accessed.</p><div className="grid grid-cols-2 md:grid-cols-5 gap-2 mt-4">{DEMOS.map(([route, label, Icon, body]) => <button key={route} type="button" disabled={busy} onClick={() => run(route, body, label)} className="p-3 rounded-xl border border-slate-800 bg-slate-900/70 hover:border-cyan-500/50 text-left disabled:opacity-50"><Icon size={16} className="text-cyan-300" /><span className="block text-[10px] text-slate-300 mt-2">{label}</span></button>)}</div>{result && <div className="mt-4 rounded-xl border border-cyan-500/20 bg-slate-950/60 p-4"><div className="flex items-center gap-2 text-cyan-300 text-xs font-semibold"><Activity size={14} /> {result.label}</div><pre className="mt-3 max-h-56 overflow-auto text-[10px] text-slate-300 whitespace-pre-wrap">{JSON.stringify(result.value, null, 2)}</pre></div>}</section>;
}
