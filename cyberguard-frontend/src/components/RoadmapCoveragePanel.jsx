import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Banknote, BrainCircuit, Globe2, KeyRound, Network, Scale, Users } from 'lucide-react';

const emptyState = { economics: null, honeytokens: null, bias: null, immunity: null, resource: null, attention: null, jurisdiction: null, compliance: null };

export default function RoadmapCoveragePanel({ apiBaseUrl, accessToken, userRole, incidents = [] }) {
  const [data, setData] = useState(emptyState);
  const [providers, setProviders] = useState(null);
  const [integrationMessage, setIntegrationMessage] = useState(null);
  const [busy, setBusy] = useState(false);
  const selected = incidents[0];
  const headers = { Authorization: `Bearer ${accessToken}` };

  useEffect(() => {
    if (!accessToken) return undefined;
    const incidentId = selected?.database_id;
    if (!incidentId) {
      setData(emptyState);
      return undefined;
    }
    setBusy(true);
    Promise.allSettled([
      axios.get(`${apiBaseUrl}/api/v1/integrations/status`, { headers }),
      axios.get(`${apiBaseUrl}/api/v1/roadmap/economics/${incidentId}`, { headers }),
      axios.post(`${apiBaseUrl}/api/v1/roadmap/honeytokens`, { incident_id: incidentId, count: 3 }, { headers }),
      axios.get(`${apiBaseUrl}/api/v1/roadmap/bias`, { headers }),
      axios.get(`${apiBaseUrl}/api/v1/roadmap/immunity`, { headers }),
      axios.get(`${apiBaseUrl}/api/v1/roadmap/resource/${incidentId}`, { headers }),
      axios.get(`${apiBaseUrl}/api/v1/roadmap/attention`, { headers }),
      axios.get(`${apiBaseUrl}/api/v1/roadmap/jurisdiction/${incidentId}`, { headers }),
      axios.post(`${apiBaseUrl}/api/v1/roadmap/compliance-diff`, { cves: [] }, { headers }),
    ]).then((responses) => {
      const [statusResponse, ...featureResponses] = responses;
      if (statusResponse.status === 'fulfilled') setProviders(statusResponse.value.data.providers);
      const keys = Object.keys(emptyState);
      const next = { ...emptyState };
      featureResponses.forEach((response, index) => {
        if (response.status === 'fulfilled') next[keys[index]] = response.value.data;
      });
      setData(next);
    }).finally(() => setBusy(false));
    return undefined;
  }, [accessToken, apiBaseUrl, selected?.database_id]);

  const deployHoneytokens = async () => {
    if (!data.honeytokens?.tokens?.length) return;
    const response = await axios.post(`${apiBaseUrl}/api/v1/roadmap/honeytokens/deploy`, { incident_id: selected.database_id, tokens: data.honeytokens.tokens }, { headers });
    setIntegrationMessage(`Honeytokens: ${response.data.status}`);
  };

  const syncCves = async () => {
    const response = await axios.post(`${apiBaseUrl}/api/v1/roadmap/compliance-diff/sync`, {}, { headers });
    setIntegrationMessage(`CVE feed: ${response.data.feed.status}`);
  };

  if (!selected) return <section className="glass-panel p-5 text-sm text-slate-400">Analyze an incident to activate the remaining roadmap simulations.</section>;

  return <section className="glass-panel p-5 xl:col-span-2">
    <div className="panel-heading"><div><div className="eyebrow flex items-center gap-2"><BrainCircuit size={13} /> Roadmap coverage</div><h3>Advanced SOC decision support</h3></div><span className="text-[10px] text-cyan-300">{busy ? 'SYNCING' : 'LIVE PREVIEW'}</span></div>
    <div className="flex flex-wrap items-center gap-2 mt-4"><span className="text-[10px] text-slate-400">Providers: honeytokens {providers?.honeytokens?.configured ? 'ready' : 'not configured'} · CVE feed {providers?.cve_feed?.configured ? 'ready' : 'not configured'} · tenant exchange {providers?.tenant_immunity?.configured ? 'ready' : 'not configured'}</span><button type="button" onClick={deployHoneytokens} disabled={userRole !== 'head_admin' || !providers?.honeytokens?.configured} className="px-2 py-1 rounded border border-amber-500/30 text-[10px] text-amber-200 disabled:opacity-40">Deploy staged canaries</button><button type="button" onClick={syncCves} disabled={userRole !== 'head_admin' || !providers?.cve_feed?.configured} className="px-2 py-1 rounded border border-fuchsia-500/30 text-[10px] text-fuchsia-200 disabled:opacity-40">Sync CVE feed</button>{integrationMessage && <span className="text-[10px] text-emerald-300">{integrationMessage}</span>}</div><div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3 mt-4">
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
