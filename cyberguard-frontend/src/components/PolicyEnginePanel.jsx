import React, { useEffect, useState } from 'react';
import axios from 'axios';

const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

const blankPolicy = { name: '', description: '', category: 'all', threshold: 70, severity: 'HIGH', action: 'require_mfa', approval_required: true, enabled: true };

export default function PolicyEnginePanel({ accessToken, userRole }) {
  const [policies, setPolicies] = useState(null);
  const [policy, setPolicy] = useState(blankPolicy);
  const [editingId, setEditingId] = useState(null);
  const [incidentId, setIncidentId] = useState('');
  const [evaluation, setEvaluation] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const canManage = userRole === 'head_admin';

  const headers = { Authorization: `Bearer ${accessToken}` };

  const refresh = async () => {
    const [policyResponse, incidentResponse] = await Promise.all([
      axios.get(`${apiBaseUrl}/api/v1/prevention/policies`, { headers }),
      axios.get(`${apiBaseUrl}/api/v1/incidents`, { headers }),
    ]);
    setPolicies(policyResponse.data);
    const latestIncident = incidentResponse.data.incidents?.[0];
    if (latestIncident && !incidentId) setIncidentId(String(latestIncident.database_id));
  };

  useEffect(() => {
    if (!accessToken) return;
    let active = true;
    const requestHeaders = { Authorization: `Bearer ${accessToken}` };
    Promise.all([
      axios.get(`${apiBaseUrl}/api/v1/prevention/policies`, { headers: requestHeaders }),
      axios.get(`${apiBaseUrl}/api/v1/incidents`, { headers: requestHeaders }),
    ])
      .then(([policyResponse, incidentResponse]) => {
        if (!active) return;
        setPolicies(policyResponse.data);
        const latestIncident = incidentResponse.data.incidents?.[0];
        if (latestIncident) setIncidentId(String(latestIncident.database_id));
      })
      .catch((requestError) => {
        if (active) setError(requestError.response?.data?.detail || 'Policy service unavailable.');
      });
    return () => { active = false; };
  }, [accessToken]);

  const savePolicy = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (editingId) {
        await axios.put(`${apiBaseUrl}/api/v1/prevention/policies/${editingId}`, policy, { headers });
      } else {
        await axios.post(`${apiBaseUrl}/api/v1/prevention/policies`, policy, { headers });
      }
      setPolicy(blankPolicy);
      setEditingId(null);
      await refresh();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Policy could not be saved.');
    } finally {
      setBusy(false);
    }
  };

  const deactivatePolicy = async (policyId) => {
    setBusy(true);
    setError(null);
    try {
      await axios.delete(`${apiBaseUrl}/api/v1/prevention/policies/${policyId}`, { headers });
      if (editingId === policyId) { setEditingId(null); setPolicy(blankPolicy); }
      await refresh();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Policy could not be deactivated.');
    } finally {
      setBusy(false);
    }
  };

  const evaluateLatest = async () => {
    if (!incidentId) return;
    setBusy(true);
    setError(null);
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/prevention/policies/evaluate`, { incident_id: Number(incidentId) }, { headers });
      setEvaluation(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Policy evaluation failed.');
    } finally {
      setBusy(false);
    }
  };

  const editPolicy = (item) => {
    setEditingId(item.policy_id);
    setPolicy({ ...item });
  };

  if (!policies) return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">{error || 'Loading policy engine...'}</section>;

  return (
    <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg">
      <p className="eyebrow">Policy engine</p>
      <h2 className="text-xl font-bold text-white mt-1">Adaptive Prevention Policies</h2>
      <div className="mt-4 rounded-lg border border-violet-500/25 bg-violet-500/5 p-3 text-xs text-violet-100">
        <div>Policy records: {policies.policies.length}</div>
        <div className="mt-2">Access: {canManage ? 'management enabled' : 'read only'}</div>
        <div className="mt-2">Status: {policies.status?.replaceAll('_', ' ')}</div>
      </div>
      {error && <div role="alert" className="mt-3 text-xs text-rose-300">{error}</div>}
      <div className="mt-4 space-y-2">{policies.policies.map((item) => <div key={item.policy_id} className="flex flex-wrap items-center gap-3 rounded border border-slate-700 p-3 text-xs text-slate-300"><div className="min-w-0 flex-1"><strong className="text-slate-100">{item.name}</strong><div className="mt-1">{item.category} · score ≥ {item.threshold} · {item.severity} · {item.action} · v{item.version}{item.enabled ? '' : ' · disabled'}</div><div className="mt-1 text-[10px] text-slate-500">{item.description}</div></div>{canManage && item.enabled && <><button type="button" onClick={() => editPolicy(item)} className="rounded border border-slate-600 px-2 py-1 text-[10px]">Edit</button><button type="button" disabled={busy} onClick={() => deactivatePolicy(item.policy_id)} className="rounded border border-rose-500/40 px-2 py-1 text-[10px] text-rose-300 disabled:opacity-50">Deactivate</button></>}</div>)}</div>
      {canManage && <form onSubmit={savePolicy} className="mt-4 grid gap-3 border-t border-slate-700/60 pt-4 sm:grid-cols-2">
        <label className="grid gap-1 text-[11px] text-slate-400">Name<input required maxLength={120} value={policy.name} onChange={(event) => setPolicy((current) => ({ ...current, name: event.target.value }))} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label>
        <label className="grid gap-1 text-[11px] text-slate-400">Category<input required maxLength={40} value={policy.category} onChange={(event) => setPolicy((current) => ({ ...current, category: event.target.value }))} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label>
        <label className="grid gap-1 text-[11px] text-slate-400">Risk threshold<input type="number" min="0" max="100" value={policy.threshold} onChange={(event) => setPolicy((current) => ({ ...current, threshold: Number(event.target.value) }))} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label>
        <label className="grid gap-1 text-[11px] text-slate-400">Action<select value={policy.action} onChange={(event) => setPolicy((current) => ({ ...current, action: event.target.value }))} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200"><option value="monitor">Monitor</option><option value="require_mfa">Require MFA</option><option value="block">Block recommendation</option><option value="isolate">Isolate recommendation</option><option value="open_incident">Open incident</option><option value="contain">Contain recommendation</option></select></label>
        <label className="grid gap-1 text-[11px] text-slate-400 sm:col-span-2">Description<textarea maxLength={1000} value={policy.description} onChange={(event) => setPolicy((current) => ({ ...current, description: event.target.value }))} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label>
        <label className="flex items-center gap-2 text-[11px] text-slate-300"><input type="checkbox" checked={policy.approval_required} onChange={(event) => setPolicy((current) => ({ ...current, approval_required: event.target.checked }))} />Approval required</label>
        <button type="submit" disabled={busy} className="rounded border border-cyan-500/30 px-3 py-2 text-xs text-cyan-200 disabled:opacity-50">{busy ? 'Saving…' : editingId ? 'Save version' : 'Create policy'}</button>
      </form>}
      <div className="mt-4 flex flex-wrap items-end gap-2 border-t border-slate-700/60 pt-4"><label className="grid gap-1 text-[11px] text-slate-400">Incident database ID<input type="number" min="1" value={incidentId} onChange={(event) => setIncidentId(event.target.value)} className="rounded border border-slate-700 bg-slate-950 p-2 text-xs text-slate-200" /></label><button type="button" disabled={busy || !incidentId} onClick={evaluateLatest} className="rounded border border-amber-500/30 px-3 py-2 text-xs text-amber-200 disabled:opacity-50">Evaluate policies</button></div>
      {evaluation && <div className="mt-3 rounded border border-slate-700 p-3 text-xs text-slate-300"><div>Evaluation: recommendation only · {evaluation.matched_policies.length} match(es) · approval {evaluation.approval_required ? 'required' : 'not required'}</div><div className="mt-1">Actions: {evaluation.actions.join(', ') || 'none'}</div></div>}
    </section>
  );
}
