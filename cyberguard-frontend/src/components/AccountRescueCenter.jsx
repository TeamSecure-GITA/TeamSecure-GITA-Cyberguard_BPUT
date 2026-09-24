import React, { useState } from 'react';
import axios from 'axios';
import { AlertTriangle, CheckCircle2, Download, FileText, LockKeyhole, Play, Radar, ShieldCheck, Siren, Smartphone, Undo2 } from 'lucide-react';

const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

function RiskBar({ score }) {
  const color = score >= 80 ? '#fb7185' : score >= 50 ? '#fbbf24' : '#34d399';
  return <div className="h-3 overflow-hidden rounded-full bg-slate-800"><div className="h-full transition-all duration-700" style={{ width: `${score}%`, background: color }} /></div>;
}

export default function AccountRescueCenter({ accessToken }) {
  const [scan, setScan] = useState(null);
  const [plan, setPlan] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [guardian, setGuardian] = useState(null);
  const [blastRadius, setBlastRadius] = useState(null);
  const [lockedOut, setLockedOut] = useState(null);
  const [simulation, setSimulation] = useState(null);
  const [capabilities, setCapabilities] = useState(null);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const headers = { Authorization: `Bearer ${accessToken}` };

  const scanAccount = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/rescue/scan`, { provider: 'generic', unknown_session: true, suspicious_login: true, new_oauth_app: true, forwarding_rule: true, mfa_enabled: false, recovery_changed: false, breach_history: true }, { headers });
      setScan(response.data);
      const planResponse = await axios.post(`${apiBaseUrl}/api/v1/rescue/plan`, { scan: response.data }, { headers });
      setPlan(planResponse.data);
      const evidenceResponse = await axios.post(`${apiBaseUrl}/api/v1/rescue/evidence`, { scan: response.data, account_label: 'connected account' }, { headers });
      setEvidence(evidenceResponse.data);
      setMessage('Scan complete. Your personalized rescue plan is ready.');
    } catch (error) {
      setMessage(error.response?.data?.detail || 'Account scan could not be completed.');
    } finally { setBusy(false); }
  };

  const runStep = async (step) => {
    if (step.confirmation === 'explicit' && !window.confirm(`Confirm: ${step.title}? CyberGuard will use only authorized provider permissions.`)) return;
    setBusy(true);
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/rescue/step`, { plan, step_id: step.id, confirmed: true }, { headers });
      setMessage(response.data.message || `${step.title}: ${response.data.status}`);
      setPlan((current) => ({ ...current, steps: current.steps.map((item) => item.id === step.id ? { ...item, status: response.data.status, verified: response.data.verified } : item) }));
    } catch (error) { setMessage(error.response?.data?.detail || 'Rescue step failed safely.'); } finally { setBusy(false); }
  };

  const lockdown = async () => {
    if (!window.confirm('Emergency Lockdown requires explicit confirmation and may sign out every unknown device. Continue?')) return;
    setBusy(true);
    try { const response = await axios.post(`${apiBaseUrl}/api/v1/rescue/lockdown`, { scan, confirmed: true }, { headers }); setMessage(`Emergency Lockdown: ${response.data.status}`); } catch (error) { setMessage(error.response?.data?.detail || 'Lockdown requires elevated approval.'); } finally { setBusy(false); }
  };

  const enableGuardian = async () => {
    try { const response = await axios.post(`${apiBaseUrl}/api/v1/rescue/guardian`, { scan, enabled: true }, { headers }); setGuardian(response.data); setMessage('Guardian Mode is monitoring the account security baseline.'); } catch (error) { setMessage(error.response?.data?.detail || 'Guardian Mode could not be enabled.'); }
  };

  const loadSafetyViews = async () => {
    const [radius, recovery, capability] = await Promise.all([axios.get(`${apiBaseUrl}/api/v1/rescue/blast-radius?provider=generic`, { headers }), axios.get(`${apiBaseUrl}/api/v1/rescue/locked-out?provider=generic`, { headers }), axios.get(`${apiBaseUrl}/api/v1/rescue/capabilities?provider=generic`, { headers })]);
    setBlastRadius(radius.data); setLockedOut(recovery.data);
    setCapabilities(capability.data);
  };

  const runSimulation = async () => {
    if (!scan) return;
    const response = await axios.post(`${apiBaseUrl}/api/v1/rescue/simulate`, { scan }, { headers });
    setSimulation(response.data);
  };

  const downloadCard = async () => {
    const response = await axios.get(`${apiBaseUrl}/api/v1/rescue/offline-card?provider=generic`, { headers });
    const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'cyberguard-offline-rescue-card.json'; anchor.click(); URL.revokeObjectURL(url);
  };

  return <section className="glass-panel p-5 border border-rose-500/20 bg-[radial-gradient(circle_at_top_right,_rgba(127,29,29,0.3),_rgba(2,6,23,0.96)_48%)]">
    <div className="panel-heading"><div><div className="eyebrow flex items-center gap-2"><Siren size={13} /> RiskShield / Account Rescue</div><h3>Detect, contain, recover, verify, monitor</h3></div><span className="text-[10px] text-amber-300">NO PASSWORDS COLLECTED</span></div>
    <p className="mt-3 text-xs text-slate-400">Metadata-only account protection. Provider write actions remain confirmation-gated and unsupported actions open the official provider flow.</p>
    <div className="mt-4 flex flex-wrap gap-2"><button type="button" onClick={scanAccount} disabled={busy} className="inline-flex items-center gap-2 rounded-lg bg-rose-600 px-4 py-2 text-xs font-semibold text-white disabled:opacity-50"><Radar size={15} /> {busy ? 'Scanning...' : 'Scan account'}</button><button type="button" onClick={lockdown} disabled={!scan || busy} className="inline-flex items-center gap-2 rounded-lg border border-rose-400/40 px-4 py-2 text-xs text-rose-200 disabled:opacity-40"><LockKeyhole size={15} /> Emergency Lockdown</button><button type="button" onClick={enableGuardian} disabled={!scan} className="inline-flex items-center gap-2 rounded-lg border border-emerald-400/40 px-4 py-2 text-xs text-emerald-200 disabled:opacity-40"><ShieldCheck size={15} /> Keep protecting my account</button></div>
    {scan && <div className="mt-5 grid gap-4 md:grid-cols-[1fr_1.4fr]"><div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4"><div className="flex items-center justify-between"><span className="text-xs text-slate-400">Account security score</span><strong className="text-3xl text-rose-300">{scan.score}/100</strong></div><RiskBar score={scan.score} /><p className="mt-2 text-xs font-semibold text-rose-200">Risk: {scan.risk_level}</p><div className="mt-4 space-y-2">{scan.top_contributors.map((finding) => <div key={finding.id} className="flex gap-2 text-[11px] text-slate-300"><AlertTriangle size={13} className="mt-0.5 text-amber-300" />{finding.description}</div>)}</div>{evidence && <p className="mt-4 text-[10px] text-emerald-300">Evidence snapshot saved for rollback until {new Date(evidence.expires_at).toLocaleDateString()}.</p>}</div><div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4"><div className="flex items-center justify-between"><h4 className="text-sm font-semibold text-white">Personalized rescue plan</h4><span className="text-[10px] text-slate-500">{plan?.steps?.length || 0} steps</span></div><div className="mt-3 space-y-2">{plan?.steps?.map((step, index) => <div key={step.id} className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/60 p-2"><span className="grid h-6 w-6 place-items-center rounded-full bg-slate-800 text-[10px] text-slate-300">{index + 1}</span><div className="min-w-0 flex-1"><p className="text-xs text-slate-200">{step.title}</p><p className="text-[10px] text-slate-500">{step.status === 'manual_required' ? step.fallback : step.status}</p></div>{step.status === 'completed' ? <CheckCircle2 size={16} className="text-emerald-300" /> : step.status === 'not_needed' ? <span className="text-[10px] text-slate-600">clear</span> : <button type="button" onClick={() => runStep(step)} disabled={busy} className="rounded border border-cyan-400/30 px-2 py-1 text-[10px] text-cyan-200 disabled:opacity-40">{step.supported ? 'Run' : 'Guide me'}</button>}</div>)}</div></div></div>}
    <div className="mt-4 flex flex-wrap gap-2"><button type="button" onClick={loadSafetyViews} disabled={!scan} className="inline-flex items-center gap-1 rounded border border-slate-700 px-3 py-2 text-[10px] text-slate-300 disabled:opacity-40"><Smartphone size={13} /> View recovery safety map</button><button type="button" onClick={runSimulation} disabled={!scan} className="inline-flex items-center gap-1 rounded border border-amber-400/30 px-3 py-2 text-[10px] text-amber-200 disabled:opacity-40"><Play size={13} /> Run rescue simulator</button><button type="button" onClick={downloadCard} className="inline-flex items-center gap-1 rounded border border-slate-700 px-3 py-2 text-[10px] text-slate-300"><Download size={13} /> Offline rescue card</button></div>
    {simulation && <div className="mt-3 rounded-lg border border-amber-400/20 bg-amber-500/5 p-3 text-xs text-amber-100"><div className="flex items-center gap-2 font-semibold"><Play size={13} /> Safe rescue simulation</div><p className="mt-1 text-[10px] text-amber-200">Projected risk: {simulation.risk_before} → {simulation.risk_after}. No provider state changed.</p></div>}
    {guardian && <div className="mt-3 rounded-lg border border-emerald-400/20 bg-emerald-500/5 p-3 text-xs text-emerald-200">Guardian Mode active for {guardian.watch_window_hours} hours. Monitoring new logins, devices, recovery changes, OAuth, forwarding, and MFA.</div>}
    {(blastRadius || lockedOut) && <div className="mt-4 grid gap-3 md:grid-cols-2">{blastRadius && <div className="rounded-lg border border-slate-800 p-3"><h4 className="text-xs font-semibold text-white">Blast radius</h4>{blastRadius.assets.map((asset) => <p key={asset.name} className="mt-2 text-[10px] text-slate-400"><strong className="text-slate-200">{asset.name}</strong> · {asset.risk} · {asset.reason}</p>)}</div>}{lockedOut && <div className="rounded-lg border border-slate-800 p-3"><h4 className="text-xs font-semibold text-white">Locked-out recovery</h4><a className="mt-2 block text-[10px] text-cyan-300 underline" href={lockedOut.official_recovery_url} target="_blank" rel="noreferrer">Open official recovery page</a>{lockedOut.steps.slice(0, 3).map((step) => <p key={step} className="mt-2 text-[10px] text-slate-400">{step}</p>)}</div>}</div>}
    {capabilities && <div className="mt-3 rounded-lg border border-slate-800 p-3"><div className="flex items-center gap-2 text-xs font-semibold text-white"><FileText size={13} /> Provider capability matrix</div><div className="mt-2 flex flex-wrap gap-2">{Object.entries(capabilities.capabilities).map(([name, capability]) => <span key={name} className={`rounded border px-2 py-1 text-[10px] ${capability.supported ? 'border-emerald-400/30 text-emerald-200' : 'border-slate-700 text-slate-400'}`}>{name}: {capability.supported ? 'API' : 'official guide'}</span>)}</div></div>}
    {message && <p className="mt-4 text-xs text-cyan-200">{message}</p>}
    <div className="mt-4 flex items-center gap-2 text-[10px] text-slate-500"><Undo2 size={13} /> Every rescue action is audited; unsupported provider actions remain manual and are never reported as verified.</div>
  </section>;
}
