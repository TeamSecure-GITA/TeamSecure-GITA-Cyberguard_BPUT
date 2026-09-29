import React, { useEffect, useState } from 'react';
import axios from 'axios';

const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function ContainmentQueue({ accessToken, userRole }) {
  const [requests, setRequests] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [incidentId, setIncidentId] = useState('');
  const [recommendation, setRecommendation] = useState(null);
  const [action, setAction] = useState('');
  const [target, setTarget] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const canReview = ['lead', 'head_admin'].includes(userRole);

  useEffect(() => {
    if (!accessToken) return;
    let active = true;
    const headers = { Authorization: `Bearer ${accessToken}` };
    Promise.all([
      axios.get(`${apiBaseUrl}/api/v1/incidents`, { headers }),
      axios.get(`${apiBaseUrl}/api/v1/containment/queue`, { headers }),
    ])
      .then(([incidentResponse, queueResponse]) => {
        if (!active) return;
        const incidentList = incidentResponse.data.incidents || [];
        setIncidents(incidentList);
        setRequests(queueResponse.data.requests || []);
        if (incidentList.length) setIncidentId((current) => current || String(incidentList[0].database_id));
      })
      .catch((requestError) => {
        if (active) setError(requestError.response?.data?.detail || 'Containment queue unavailable.');
      });
    return () => { active = false; };
  }, [accessToken]);

  useEffect(() => {
    if (!accessToken || !incidentId) return;
    let active = true;
    const headers = { Authorization: `Bearer ${accessToken}` };
    axios.post(`${apiBaseUrl}/api/v1/prevention/containment`, { incident_id: Number(incidentId) }, { headers })
      .then((response) => {
        if (!active) return;
        setRecommendation({ ...response.data, forIncidentId: Number(incidentId) });
        setAction((current) => response.data.actions.includes(current) ? current : response.data.actions[0] || '');
      })
      .catch((requestError) => {
        if (active) setError(requestError.response?.data?.detail || 'Containment recommendation unavailable.');
      });
    return () => { active = false; };
  }, [accessToken, incidentId]);

  const reloadQueue = async () => {
    const response = await axios.get(`${apiBaseUrl}/api/v1/containment/queue`, { headers: { Authorization: `Bearer ${accessToken}` } });
    setRequests(response.data.requests || []);
  };

  const submitRequest = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await axios.post(`${apiBaseUrl}/api/v1/containment/requests`, { incident_id: Number(incidentId), action, target }, { headers: { Authorization: `Bearer ${accessToken}` } });
      await reloadQueue();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Containment request failed.');
    } finally {
      setBusy(false);
    }
  };

  const transition = async (requestId, transitionName) => {
    setBusy(true);
    setError(null);
    try {
      await axios.post(`${apiBaseUrl}/api/v1/containment/requests/${requestId}/${transitionName}`, {}, { headers: { Authorization: `Bearer ${accessToken}` } });
      await reloadQueue();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Containment transition failed.');
    } finally {
      setBusy(false);
    }
  };

  const selectedIncident = incidents.find((item) => String(item.database_id) === incidentId);
  const currentRecommendation = recommendation?.forIncidentId === Number(incidentId) ? recommendation : null;

  return (
    <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg">
      <p className="eyebrow">Containment</p>
      <h2 className="text-xl font-bold text-white mt-1">Containment Queue</h2>
      {error && <div role="alert" className="mt-3 text-xs text-rose-300">{error}</div>}
      {incidents.length === 0 ? <p className="mt-4 text-xs text-slate-400">No stored incidents are available for containment review.</p> : <form onSubmit={submitRequest} className="mt-4 grid gap-3 border-b border-slate-700/60 pb-4 sm:grid-cols-2">
        <label className="grid gap-1 text-[11px] text-slate-400">Incident<select value={incidentId} onChange={(event) => setIncidentId(event.target.value)} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200">{incidents.map((incident) => <option key={incident.database_id} value={incident.database_id}>{incident.id} · {incident.category} · risk {incident.riskScore}</option>)}</select></label>
        <label className="grid gap-1 text-[11px] text-slate-400">Recommended action<select value={action} onChange={(event) => setAction(event.target.value)} disabled={!currentRecommendation?.actions.length} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200">{currentRecommendation?.actions.map((item) => <option key={item} value={item}>{item.replaceAll('_', ' ')}</option>)}</select></label>
        <label className="grid gap-1 text-[11px] text-slate-400">Target<input required maxLength={160} value={target} onChange={(event) => setTarget(event.target.value)} placeholder={selectedIncident?.id || 'Target asset or identity'} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label>
        <button type="submit" disabled={busy || !action || !target.trim()} className="self-end rounded border border-cyan-500/30 px-3 py-2 text-xs text-cyan-200 disabled:opacity-50">{busy ? 'Submitting…' : 'Request containment approval'}</button>
      </form>}
      <div className="mt-4 space-y-2">{requests.map((item) => <div key={item.request_id} className="rounded border border-slate-700 p-3 text-xs text-slate-300"><div className="flex flex-wrap items-center gap-2"><strong className="text-slate-100">INC-{String(item.incident_id).padStart(4, '0')}</strong><span>{item.action.replaceAll('_', ' ')} · {item.target}</span><span className="ml-auto uppercase">{item.status}</span></div><div className="mt-1 text-[10px] text-slate-500">Requested by {item.requested_by} · Simulation only</div>{item.execution?.message && <div className="mt-2 text-[10px] text-amber-200">{item.execution.message}</div>}{canReview && item.status === 'pending' && <div className="mt-3 flex gap-2"><button type="button" disabled={busy} onClick={() => transition(item.request_id, 'approve')} className="rounded border border-emerald-500/30 px-2 py-1 text-[10px] text-emerald-200 disabled:opacity-50">Approve</button><button type="button" disabled={busy} onClick={() => transition(item.request_id, 'reject')} className="rounded border border-rose-500/30 px-2 py-1 text-[10px] text-rose-200 disabled:opacity-50">Reject</button></div>}{canReview && item.status === 'approved' && <button type="button" disabled={busy} onClick={() => transition(item.request_id, 'execute')} className="mt-3 rounded border border-amber-500/30 px-2 py-1 text-[10px] text-amber-200 disabled:opacity-50">Run simulation</button>}</div>)}{requests.length === 0 && <p className="text-xs text-slate-400">No containment requests yet.</p>}</div>
      <p className="mt-4 text-[10px] text-slate-500">Approval is recorded and execution is simulation-only; external systems are not changed.</p>
    </section>
  );
}
