import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { getApiBaseUrl } from '../apiConfig';

const apiBaseUrl = getApiBaseUrl();

export default function IdentityTrustPanel({ accessToken }) {
  const [trust, setTrust] = useState(null);
  const [signals, setSignals] = useState({ device: 'known-device', country: '', source_ip: '', mfa_enabled: true, behavioral_anomaly: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!accessToken) return;
    axios.get(`${apiBaseUrl}/api/v1/prevention/identity-trust`, { headers: { Authorization: `Bearer ${accessToken}` } })
      .then((response) => setTrust(response.data))
      .catch(() => setTrust(null));
  }, [accessToken]);

  const submitReport = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/prevention/identity-trust`, signals, { headers: { Authorization: `Bearer ${accessToken}` } });
      setTrust(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Identity trust assessment failed.');
    } finally {
      setBusy(false);
    }
  };

  if (!trust) return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">Identity trust not available.</section>;

  return (
    <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg">
      <p className="eyebrow">Identity trust</p>
      <h2 className="text-xl font-bold text-white mt-1">Zero-Trust Identity Check</h2>
      <div className="mt-4 rounded-lg border border-cyan-500/25 bg-cyan-500/5 p-3 text-xs text-cyan-100">
        <div>Trust score: {trust.trust_score ?? 'N/A'}</div>
        <div className="mt-2">Status: {trust.status}</div>
      </div>
      <div className="mt-3 text-xs text-slate-300">{trust.message || `Required action: ${trust.required_action}`}</div>
      <form onSubmit={submitReport} className="mt-4 grid gap-3 border-t border-slate-700/60 pt-4 sm:grid-cols-2">
        <label className="grid gap-1 text-[11px] text-slate-400">Reported device<select value={signals.device} onChange={(event) => setSignals((current) => ({ ...current, device: event.target.value }))} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200"><option value="known-device">Known device</option><option value="new-device">New device</option><option value="unknown-device">Unknown device</option></select></label>
        <label className="grid gap-1 text-[11px] text-slate-400">Country code<input required minLength={2} maxLength={2} value={signals.country} onChange={(event) => setSignals((current) => ({ ...current, country: event.target.value.toUpperCase() }))} placeholder="US" className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label>
        <label className="grid gap-1 text-[11px] text-slate-400">Reported source IP<input required value={signals.source_ip} onChange={(event) => setSignals((current) => ({ ...current, source_ip: event.target.value }))} placeholder="203.0.113.10" className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label>
        <div className="grid gap-2 self-end text-[11px] text-slate-300"><label className="flex items-center gap-2"><input type="checkbox" checked={signals.mfa_enabled} onChange={(event) => setSignals((current) => ({ ...current, mfa_enabled: event.target.checked }))} />MFA enabled</label><label className="flex items-center gap-2"><input type="checkbox" checked={signals.behavioral_anomaly} onChange={(event) => setSignals((current) => ({ ...current, behavioral_anomaly: event.target.checked }))} />Behavioral anomaly reported</label></div>
        <button type="submit" disabled={busy || !accessToken} className="rounded border border-cyan-500/30 px-3 py-2 text-xs text-cyan-200 disabled:opacity-50 sm:col-span-2">{busy ? 'Assessing…' : 'Save reported login assessment'}</button>
        {error && <div role="alert" className="text-xs text-rose-300 sm:col-span-2">{error}</div>}
      </form>
      <p className="mt-3 text-[10px] text-slate-500">Signals are operator-reported; no identity-provider feed is connected.</p>
    </section>
  );
}
