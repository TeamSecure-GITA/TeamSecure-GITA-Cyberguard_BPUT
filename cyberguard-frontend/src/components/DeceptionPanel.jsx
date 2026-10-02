import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { getApiBaseUrl } from '../apiConfig';

const apiBaseUrl = getApiBaseUrl();

export default function DeceptionPanel({ accessToken }) {
  const [status, setStatus] = useState(null);
  const [event, setEvent] = useState({ host: '', actor: '', resource: '', event_type: 'access', source_ip: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!accessToken) return;
    axios.get(`${apiBaseUrl}/api/v1/prevention/deception-status`, { headers: { Authorization: `Bearer ${accessToken}` } })
      .then((response) => setStatus(response.data))
      .catch(() => setStatus(null));
  }, [accessToken]);

  const reportInteraction = async (formEvent) => {
    formEvent.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/prevention/deception-status`, event, { headers: { Authorization: `Bearer ${accessToken}` } });
      setStatus(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Deception event could not be reported.');
    } finally {
      setBusy(false);
    }
  };

  if (!status) return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">Deception status unavailable.</section>;

  return (
    <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg">
      <p className="eyebrow">Deception layer</p>
      <h2 className="text-xl font-bold text-white mt-1">Reported Decoy Interactions</h2>
      <div className="mt-4 space-y-2 text-xs text-slate-300">
        <div>Active decoys: {status.active_decoys.length}</div>
        <div>Reported interactions: {status.triggered_decoys.length}</div>
        <div>Reported hosts: {status.compromised_assets.join(', ') || 'none'}</div>
      </div>
      {status.triggered_decoys.length > 0 && <div className="mt-3 space-y-2">{status.triggered_decoys.slice(0, 5).map((item) => <div key={item.event_id} className="rounded border border-slate-700 p-2 text-[11px] text-slate-300">{item.event_type} · {item.resource} · {item.host} · incident {item.incident_id}</div>)}</div>}
      {status.message && <div className="mt-3 text-xs text-slate-400">{status.message}</div>}
      <form onSubmit={reportInteraction} className="mt-4 grid gap-3 border-t border-slate-700/60 pt-4 sm:grid-cols-2">
        <label className="grid gap-1 text-[11px] text-slate-400">Host<input required maxLength="120" value={event.host} onChange={(e) => setEvent((current) => ({ ...current, host: e.target.value }))} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label>
        <label className="grid gap-1 text-[11px] text-slate-400">Actor<input required maxLength="120" value={event.actor} onChange={(e) => setEvent((current) => ({ ...current, actor: e.target.value }))} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label>
        <label className="grid gap-1 text-[11px] text-slate-400">Resource<input required maxLength="200" value={event.resource} onChange={(e) => setEvent((current) => ({ ...current, resource: e.target.value }))} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label>
        <label className="grid gap-1 text-[11px] text-slate-400">Event type<select value={event.event_type} onChange={(e) => setEvent((current) => ({ ...current, event_type: e.target.value }))} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200"><option value="access">Access</option><option value="authentication">Authentication</option><option value="modification">Modification</option><option value="execution">Execution</option></select></label>
        <label className="grid gap-1 text-[11px] text-slate-400">Source IP (optional)<input value={event.source_ip} onChange={(e) => setEvent((current) => ({ ...current, source_ip: e.target.value }))} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label>
        <button type="submit" disabled={busy || !accessToken} className="rounded border border-cyan-500/30 px-3 py-2 text-xs text-cyan-200 disabled:opacity-50">{busy ? 'Saving…' : 'Report interaction'}</button>
        {error && <div role="alert" className="text-xs text-rose-300 sm:col-span-2">{error}</div>}
      </form>
      <p className="mt-3 text-[10px] text-slate-500">Reports are operator-submitted; no active decoy registry or interaction feed is connected.</p>
    </section>
  );
}
