import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { getApiBaseUrl } from '../apiConfig';

const apiBaseUrl = getApiBaseUrl();

export default function InsiderRiskPanel({ accessToken }) {
  const [risk, setRisk] = useState(null);
  const [activity, setActivity] = useState({ downloads: 0, off_hours: false, privilege_change: false, sensitive_access: 0 });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [loadError, setLoadError] = useState(null);

  useEffect(() => {
    if (!accessToken) return;
    axios.get(`${apiBaseUrl}/api/v1/prevention/insider-risk`, { headers: { Authorization: `Bearer ${accessToken}` } })
      .then((response) => {
        setRisk(response.data);
        setLoadError(null);
      })
      .catch((requestError) => {
        setRisk(null);
        setLoadError(requestError.response?.data?.detail || requestError.message || 'Insider risk telemetry could not be loaded.');
      });
  }, [accessToken]);

  const submitActivity = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/prevention/insider-risk`, activity, { headers: { Authorization: `Bearer ${accessToken}` } });
      setRisk(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Insider risk assessment failed.');
    } finally {
      setBusy(false);
    }
  };

  if (loadError) {
    return <section role="alert" className="bg-cardBg border border-rose-500/30 rounded-xl p-5 text-xs text-rose-200">{loadError}</section>;
  }
  if (!risk) {
    return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">Insider risk unavailable.</section>;
  }

  return (
    <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg">
      <p className="eyebrow">Insider prevention</p>
      <h2 className="text-xl font-bold text-white mt-1">Insider Threat Risk</h2>
      <div className="mt-4 rounded-lg border border-red-500/25 bg-red-500/5 p-3 text-xs text-red-100">
        <div>Risk score: {risk.risk_score ?? 'N/A'}</div>
        <div className="mt-2">Preventive action: {risk.preventive_action}</div>
      </div>
      {risk.event_count !== undefined && (
        <div className="mt-2 text-[10px] text-slate-500">
          Observed audit events: {risk.event_count} in the last {risk.observation_window_days} days.
        </div>
      )}
      {risk.message && <div className="mt-3 text-xs text-slate-400">{risk.message}</div>}
      <div className="mt-3 text-xs text-slate-300">Flags: {Object.entries(risk.flags || {}).filter(([, value]) => value).map(([key]) => key).join(', ') || 'none'}</div>
      <form onSubmit={submitActivity} className="mt-4 grid gap-3 border-t border-slate-700/60 pt-4 sm:grid-cols-2">
        <label className="grid gap-1 text-[11px] text-slate-400">Downloads reported<input type="number" min="0" max="100000" value={activity.downloads} onChange={(event) => setActivity((current) => ({ ...current, downloads: Number(event.target.value) }))} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label>
        <label className="grid gap-1 text-[11px] text-slate-400">Sensitive resources accessed<input type="number" min="0" max="100000" value={activity.sensitive_access} onChange={(event) => setActivity((current) => ({ ...current, sensitive_access: Number(event.target.value) }))} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label>
        <div className="grid gap-2 text-[11px] text-slate-300"><label className="flex items-center gap-2"><input type="checkbox" checked={activity.off_hours} onChange={(event) => setActivity((current) => ({ ...current, off_hours: event.target.checked }))} />Off-hours activity</label><label className="flex items-center gap-2"><input type="checkbox" checked={activity.privilege_change} onChange={(event) => setActivity((current) => ({ ...current, privilege_change: event.target.checked }))} />Privilege change</label></div>
        <button type="submit" disabled={busy || !accessToken} className="rounded border border-cyan-500/30 px-3 py-2 text-xs text-cyan-200 disabled:opacity-50">{busy ? 'Assessing…' : 'Save reported activity'}</button>
        {error && <div role="alert" className="text-xs text-rose-300 sm:col-span-2">{error}</div>}
      </form>
      <p className="mt-3 text-[10px] text-slate-500">
        {risk.assessment_source === 'application_audit_telemetry'
          ? 'Observed application audit events supplement the operator report. Endpoint and identity-provider telemetry are not connected.'
          : 'No application audit signals were observed; the displayed assessment is operator-reported. Endpoint telemetry is not connected.'}
      </p>
    </section>
  );
}
