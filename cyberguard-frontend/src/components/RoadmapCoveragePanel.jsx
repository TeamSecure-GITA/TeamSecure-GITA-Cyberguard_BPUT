import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Banknote, BrainCircuit, Globe2, KeyRound, Network, Scale, Users } from 'lucide-react';

const emptyState = { economics: null, honeytokens: null, bias: null, immunity: null, resource: null, attention: null, jurisdiction: null, compliance: null };
const previewIncident = { database_id: null, id: 'PREVIEW-001', category: 'phishing', risk_score: 72, riskScore: 72, risk_level: 'High', riskLevel: 'High', payload: 'Urgent credential request from a look-alike domain', assigned_to: 'analyst', status: 'Investigating', metadata: { country: 'IN' } };
const previewData = {
  economics: { total_exposure: 16840, delay_cost: 1210, mode: 'local preview' },
  honeytokens: { tokens: [{ token_id: 'HT-PREVIEW-01' }, { token_id: 'HT-PREVIEW-02' }, { token_id: 'HT-PREVIEW-03' }], mode: 'local preview' },
  bias: { status: 'no strong bias signal', analysts: [{ analyst: 'analyst' }] },
  immunity: { signature_count: 1, status: 'ready' },
  resource: { tier: 'organized', resource_score: 68 },
  attention: { total_events: 3 },
  jurisdiction: { jurisdiction: 'India', regulations: ['DPDP Act', 'CERT-In 6-hour reporting'] },
  compliance: { status: 'attention required', gap_count: 1 },
};

export default function RoadmapCoveragePanel({ apiBaseUrl, accessToken, userRole, incidents = [] }) {
  const [data, setData] = useState(emptyState);
  const [providers, setProviders] = useState(null);
  const [integrationMessage, setIntegrationMessage] = useState(null);
  const [integrationError, setIntegrationError] = useState(null);
  const [providerAction, setProviderAction] = useState(false);
  const [ticketSummary, setTicketSummary] = useState('');
  const [ticketDescription, setTicketDescription] = useState('');
  const [identityTarget, setIdentityTarget] = useState('');
  const [endpointTarget, setEndpointTarget] = useState('');
  const [loadedSelectionKey, setLoadedSelectionKey] = useState(null);
  const selected = incidents[0] || previewIncident;
  const selectedId = selected.id;
  const incidentId = selected.database_id;
  const selectionKey = `${apiBaseUrl}:${accessToken || ''}:${incidentId ?? 'preview'}:${selectedId}`;
  const busy = Boolean(accessToken) && loadedSelectionKey !== selectionKey;
  const headers = { Authorization: `Bearer ${accessToken}` };

  useEffect(() => {
    if (!accessToken) return undefined;
    const requestHeaders = { Authorization: `Bearer ${accessToken}` };
    let active = true;
    Promise.allSettled([
      axios.get(`${apiBaseUrl}/api/v1/integrations/status`, { headers: requestHeaders }),
      incidentId ? axios.get(`${apiBaseUrl}/api/v1/roadmap/economics/${incidentId}`, { headers: requestHeaders }) : Promise.resolve({ data: { ...previewData.economics, incident_id: selectedId } }),
      axios.post(`${apiBaseUrl}/api/v1/roadmap/honeytokens`, { incident_id: incidentId, count: 3 }, { headers: requestHeaders }).catch(() => ({
        data: {
          incident_id: selectedId,
          tokens: [{ token_id: 'HT-PREVIEW-01' }, { token_id: 'HT-PREVIEW-02' }, { token_id: 'HT-PREVIEW-03' }],
          mode: 'local preview',
        },
      })),
      axios.get(`${apiBaseUrl}/api/v1/roadmap/bias`, { headers: requestHeaders }),
      axios.get(`${apiBaseUrl}/api/v1/roadmap/immunity`, { headers: requestHeaders }),
      incidentId ? axios.get(`${apiBaseUrl}/api/v1/roadmap/resource/${incidentId}`, { headers: requestHeaders }) : Promise.resolve({ data: previewData.resource }),
      axios.get(`${apiBaseUrl}/api/v1/roadmap/attention`, { headers: requestHeaders }),
      incidentId ? axios.get(`${apiBaseUrl}/api/v1/roadmap/jurisdiction/${incidentId}`, { headers: requestHeaders }) : Promise.resolve({ data: previewData.jurisdiction }),
      axios.post(`${apiBaseUrl}/api/v1/roadmap/compliance-diff`, { cves: [] }, { headers: requestHeaders }),
    ]).then((responses) => {
      if (!active) return;
      const [statusResponse, ...featureResponses] = responses;
      if (statusResponse.status === 'fulfilled') setProviders(statusResponse.value.data);
        const keys = Object.keys(emptyState);
        const next = { ...previewData };
      featureResponses.forEach((response, index) => {
        if (response.status === 'fulfilled') next[keys[index]] = response.value.data;
      });
      setData(next);
    }).catch(() => {}).finally(() => { if (active) setLoadedSelectionKey(selectionKey); });
    return () => { active = false; };
  }, [accessToken, apiBaseUrl, incidentId, selectedId, selectionKey]);

  const deployHoneytokens = async () => {
    if (!data.honeytokens?.tokens?.length) return;
    const response = await axios.post(`${apiBaseUrl}/api/v1/roadmap/honeytokens/deploy`, { incident_id: selected.database_id, tokens: data.honeytokens.tokens }, { headers });
    setIntegrationMessage(`Honeytokens: ${response.data.status}`);
  };

  const syncCves = async () => {
    const response = await axios.post(`${apiBaseUrl}/api/v1/roadmap/compliance-diff/sync`, {}, { headers });
    setIntegrationMessage(`CVE feed: ${response.data.feed.status}`);
    setData((current) => ({ ...current, compliance: response.data.diff }));
  };

  const publishImmunity = () => runProviderAction('/api/v1/roadmap/immunity/publish', {}, 'Shared immunity');

  const runProviderAction = async (path, payload, label) => {
    setProviderAction(true);
    setIntegrationError(null);
    try {
      const response = await axios.post(`${apiBaseUrl}${path}`, payload, { headers });
      const count = response.data.published === undefined ? '' : ` (${response.data.published} signatures)`;
      setIntegrationMessage(`${response.data.provider || label}: ${response.data.status}${count}`);
    } catch (error) {
      setIntegrationError(error.response?.data?.detail || error.message || `${label} failed`);
    } finally {
      setProviderAction(false);
    }
  };

  const createTicket = () => runProviderAction('/api/v1/integrations/tickets', {
    summary: ticketSummary.trim(),
    description: ticketDescription.trim(),
    urgency: 2,
  }, 'Ticket creation');

  const disableIdentity = () => {
    const identity = identityTarget.trim();
    if (!identity || !window.confirm(`Suspend identity ${identity} in the configured provider?`)) return;
    return runProviderAction('/api/v1/integrations/identity/disable', { identity, confirmed: true }, 'Identity suspension');
  };

  const isolateEndpoint = () => {
    const endpointId = endpointTarget.trim();
    if (!endpointId || !window.confirm(`Isolate endpoint ${endpointId} using the configured EDR provider?`)) return;
    return runProviderAction('/api/v1/integrations/endpoint/isolate', { endpoint_id: endpointId, confirmed: true }, 'Endpoint isolation');
  };

  const productionActions = providers?.production_actions || {};
  const isHeadAdmin = userRole === 'head_admin';

  return <section className="glass-panel p-5 xl:col-span-2">
    <div className="panel-heading"><div><div className="eyebrow flex items-center gap-2"><BrainCircuit size={13} /> Roadmap coverage</div><h3>Advanced SOC decision support</h3></div><span className="text-[10px] text-cyan-300">{busy ? 'SYNCING' : 'LIVE PREVIEW'}</span></div>
    <div className="flex flex-wrap items-center gap-2 mt-4"><span className="text-[10px] text-slate-400">Providers: honeytokens {providers?.honeytokens?.configured ? 'ready' : 'not configured'} · CVE feed {providers?.cve_feed?.configured ? 'ready' : 'not configured'} · tenant exchange {providers?.tenant_immunity?.configured ? 'ready' : 'not configured'}</span><button type="button" onClick={deployHoneytokens} disabled={userRole !== 'head_admin' || !providers?.honeytokens?.configured} className="px-2 py-1 rounded border border-amber-500/30 text-[10px] text-amber-200 disabled:opacity-40">Deploy staged canaries</button><button type="button" onClick={syncCves} disabled={userRole !== 'head_admin' || !providers?.cve_feed?.configured} className="px-2 py-1 rounded border border-fuchsia-500/30 text-[10px] text-fuchsia-200 disabled:opacity-40">Sync CVE feed</button><button type="button" onClick={publishImmunity} disabled={userRole !== 'head_admin' || providerAction || !providers?.tenant_immunity?.configured} className="px-2 py-1 rounded border border-cyan-500/30 text-[10px] text-cyan-200 disabled:opacity-40">Publish shared immunity</button>{integrationMessage && <span role="status" className="text-[10px] text-emerald-300">{integrationMessage}</span>}</div>
    <section className="mt-5 border-y border-slate-700/60 py-4" aria-label="External response actions">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div><p className="eyebrow">External response</p><h4 className="text-sm font-semibold text-slate-100">Ticketing and containment</h4></div>
        <span className="text-[10px] text-slate-400">{isHeadAdmin ? 'Head administrator' : 'Head administrator access required'}</span>
      </div>
      <div className="mt-3 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <form className="space-y-2" onSubmit={(event) => { event.preventDefault(); createTicket(); }}>
          <label className="block text-[11px] text-slate-300" htmlFor="provider-ticket-summary">Incident summary</label>
          <input id="provider-ticket-summary" value={ticketSummary} onChange={(event) => setTicketSummary(event.target.value)} maxLength={200} required className="w-full rounded border border-slate-700 bg-slate-950/70 px-2.5 py-2 text-xs text-white" placeholder="Security incident summary" />
          <label className="block text-[11px] text-slate-300" htmlFor="provider-ticket-description">Description</label>
          <textarea id="provider-ticket-description" value={ticketDescription} onChange={(event) => setTicketDescription(event.target.value)} maxLength={5000} rows={2} className="w-full resize-y rounded border border-slate-700 bg-slate-950/70 px-2.5 py-2 text-xs text-white" placeholder="Evidence and recommended action" />
          <button type="submit" disabled={!isHeadAdmin || providerAction || !(productionActions.jira?.configured || productionActions.servicenow?.configured)} className="rounded border border-cyan-500/30 px-3 py-1.5 text-[11px] text-cyan-200 disabled:opacity-40">{providerAction ? 'Sending…' : 'Create provider ticket'}</button>
        </form>
        <div className="space-y-2">
          <label className="block text-[11px] text-slate-300" htmlFor="provider-identity-target">Identity to suspend</label>
          <input id="provider-identity-target" value={identityTarget} onChange={(event) => setIdentityTarget(event.target.value)} className="w-full rounded border border-slate-700 bg-slate-950/70 px-2.5 py-2 text-xs text-white" placeholder="Provider user ID or email" />
          <p className="text-[10px] text-slate-500">Okta {productionActions.okta?.configured ? 'ready' : 'not configured'} · Microsoft Graph {productionActions.microsoft_graph?.configured ? 'ready' : 'not configured'}</p>
          <button type="button" onClick={disableIdentity} disabled={!isHeadAdmin || providerAction || !identityTarget.trim() || !(productionActions.okta?.configured || productionActions.microsoft_graph?.configured)} className="rounded border border-rose-500/30 px-3 py-1.5 text-[11px] text-rose-200 disabled:opacity-40">Suspend identity…</button>
        </div>
        <div className="space-y-2">
          <label className="block text-[11px] text-slate-300" htmlFor="provider-endpoint-target">Endpoint ID to isolate</label>
          <input id="provider-endpoint-target" value={endpointTarget} onChange={(event) => setEndpointTarget(event.target.value)} className="w-full rounded border border-slate-700 bg-slate-950/70 px-2.5 py-2 text-xs text-white" placeholder="EDR endpoint ID" />
          <p className="text-[10px] text-slate-500">EDR {productionActions.edr?.configured ? 'ready' : 'not configured'}</p>
          <button type="button" onClick={isolateEndpoint} disabled={!isHeadAdmin || providerAction || !endpointTarget.trim() || !productionActions.edr?.configured} className="rounded border border-orange-500/30 px-3 py-1.5 text-[11px] text-orange-200 disabled:opacity-40">Isolate endpoint…</button>
        </div>
      </div>
      {integrationError && <p role="alert" className="mt-3 text-xs text-rose-300">{integrationError}</p>}
    </section>
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3 mt-4">
      <article className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3"><Banknote size={16} className="text-emerald-300" /><p className="text-[10px] text-slate-400 mt-2">Breach economics</p><strong className="text-lg text-white">${data.economics?.total_exposure?.toLocaleString() || '--'}</strong><small className="block text-[10px] text-slate-500">delay cost ${data.economics?.delay_cost?.toLocaleString() || '--'}</small></article>
      <article className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-3"><KeyRound size={16} className="text-amber-300" /><p className="text-[10px] text-slate-400 mt-2">Adaptive honeytokens</p><strong className="text-lg text-white">{data.honeytokens?.tokens?.length || 0} staged</strong><small className="block text-[10px] text-slate-500">simulation-only canaries</small></article>
      <article className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-3"><Users size={16} className="text-rose-300" /><p className="text-[10px] text-slate-400 mt-2">Analyst bias</p><strong className="text-sm text-white">{data.bias?.status || '--'}</strong><small className="block text-[10px] text-slate-500">{data.bias?.analysts?.length || 0} analysts observed</small></article>
      <article className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-3"><Network size={16} className="text-cyan-300" /><p className="text-[10px] text-slate-400 mt-2">Shared immunity</p><strong className="text-lg text-white">{data.immunity?.signature_count ?? '--'}</strong><small className="block text-[10px] text-slate-500">one-way signatures</small></article>
      <article className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-3"><Scale size={16} className="text-orange-300" /><p className="text-[10px] text-slate-400 mt-2">Attacker resources</p><strong className="text-sm text-white">{data.resource?.tier || '--'}</strong><small className="block text-[10px] text-slate-500">score {data.resource?.resource_score ?? '--'}</small></article>
      <article className="rounded-xl border border-sky-500/20 bg-sky-500/5 p-3"><BrainCircuit size={16} className="text-sky-300" /><p className="text-[10px] text-slate-400 mt-2">Attention surface</p><strong className="text-lg text-white">{data.attention?.total_events ?? '--'}</strong><small className="block text-[10px] text-slate-500">observational events</small></article>
      <article className="rounded-xl border border-violet-500/20 bg-violet-500/5 p-3 md:col-span-2"><Globe2 size={16} className="text-violet-300" /><p className="text-[10px] text-slate-400 mt-2">Regulatory routing</p><strong className="text-sm text-white">{data.jurisdiction?.jurisdiction || '--'}</strong><small className="block text-[10px] text-slate-500">{(data.jurisdiction?.regulations || []).join(' · ')}</small></article>
      <article className="rounded-xl border border-fuchsia-500/20 bg-fuchsia-500/5 p-3 md:col-span-2"><Scale size={16} className="text-fuchsia-300" /><p className="text-[10px] text-slate-400 mt-2">Compliance diff</p><strong className="text-sm text-white">{data.compliance?.status || '--'}</strong><small className="block text-[10px] text-slate-500">{data.compliance?.gap_count ?? '--'} control/CVE gaps</small></article>
    </div>
  </section>;
}
