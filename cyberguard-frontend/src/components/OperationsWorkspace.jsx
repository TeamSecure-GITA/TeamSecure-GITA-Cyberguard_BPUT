import React, { useCallback, useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import { getApiBaseUrl } from '../apiConfig';

const sections = ['Incidents', 'Campaigns', 'Playbooks', 'IOC lookup'];

export default function OperationsWorkspace({ accessToken, incidents = [] }) {
  const apiBaseUrl = getApiBaseUrl();
  const headers = useMemo(() => ({ Authorization: `Bearer ${accessToken}` }), [accessToken]);
  const [section, setSection] = useState('Incidents');
  const [incidentId, setIncidentId] = useState('');
  const [timeline, setTimeline] = useState([]);
  const [memory, setMemory] = useState(null);
  const [comment, setComment] = useState('');
  const [campaigns, setCampaigns] = useState([]);
  const [selectedCampaign, setSelectedCampaign] = useState(null);
  const [playbooks, setPlaybooks] = useState([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState('');
  const [plan, setPlan] = useState(null);
  const [ioc, setIoc] = useState('');
  const [iocResults, setIocResults] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const activeIncidentId = incidentId || String(incidents[0]?.database_id || '');

  const loadIncidentContext = useCallback(async (id) => {
    if (!id) return;
    setBusy(true);
    setError('');
    try {
      const [timelineResponse, memoryResponse] = await Promise.all([
        axios.get(`${apiBaseUrl}/api/v1/incidents/${id}/timeline`, { headers }),
        axios.get(`${apiBaseUrl}/api/v1/incidents/${id}/memory`, { headers }),
      ]);
      setTimeline(timelineResponse.data.events || []);
      setMemory(memoryResponse.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Could not load incident context.');
    } finally {
      setBusy(false);
    }
  }, [apiBaseUrl, headers]);

  useEffect(() => {
    if (section === 'Campaigns') {
      axios.get(`${apiBaseUrl}/api/v1/campaigns`, { headers })
        .then((response) => setCampaigns(response.data.campaigns || []))
        .catch((requestError) => setError(requestError.response?.data?.detail || 'Could not load campaigns.'));
    }
    if (section === 'Playbooks') {
      axios.get(`${apiBaseUrl}/api/v1/playbooks`, { headers })
        .then((response) => {
          const rows = response.data.playbooks || [];
          setPlaybooks(rows);
          setSelectedPlaybook((current) => current || rows[0]?.id || '');
        })
        .catch((requestError) => setError(requestError.response?.data?.detail || 'Could not load playbooks.'));
    }
  }, [section, apiBaseUrl, headers]);

  const addComment = async (event) => {
    event.preventDefault();
    if (!activeIncidentId || !comment.trim()) return;
    setBusy(true);
    setError('');
    try {
      await axios.post(`${apiBaseUrl}/api/v1/incidents/${activeIncidentId}/comments`, { comment: comment.trim() }, { headers });
      setComment('');
      await loadIncidentContext(activeIncidentId);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Could not save the analyst note.');
    } finally {
      setBusy(false);
    }
  };

  const previewPlaybook = async () => {
    const selected = playbooks.find((item) => item.id === selectedPlaybook);
    const incident = incidents.find((item) => String(item.database_id) === activeIncidentId);
    if (!selected || !incident) {
      setError('Select a playbook and an incident before creating a plan.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const detail = await axios.get(`${apiBaseUrl}/api/v1/incidents/${activeIncidentId}`, { headers });
      const response = await axios.post(`${apiBaseUrl}/api/v1/playbooks/plan`, {
        playbook: selected,
        assessment: detail.data.incident.assessment || {},
        approved: false,
      }, { headers });
      setPlan(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Could not create the playbook plan.');
    } finally {
      setBusy(false);
    }
  };

  const lookupIoc = async (event) => {
    event.preventDefault();
    if (!ioc.trim()) return;
    setBusy(true);
    setError('');
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/threat-intel/lookup`, { value: ioc.trim() }, { headers });
      setIocResults(response.data);
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'IOC lookup failed.');
    } finally {
      setBusy(false);
    }
  };

  const selectIncident = (value) => {
    setIncidentId(value);
    setTimeline([]);
    setMemory(null);
  };

  return (
    <section className="space-y-5 rounded-2xl border border-slate-700/80 bg-slate-950/70 p-4 sm:p-6">
      <header>
        <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-cyan-400">SOC Operations</p>
        <h2 className="mt-1 text-xl font-bold text-white">Casework and response</h2>
        <p className="mt-1 text-xs text-slate-400">Review incident history, campaign links, playbook plans, and local IOC evidence.</p>
      </header>
      <nav className="flex flex-wrap gap-2" aria-label="Operations sections">
        {sections.map((item) => (
          <button key={item} type="button" onClick={() => { setSection(item); setError(''); }} aria-pressed={section === item}
            className={`rounded-lg border px-3 py-2 text-xs font-semibold ${section === item ? 'border-cyan-400/50 bg-cyan-500/15 text-cyan-200' : 'border-slate-700 text-slate-300 hover:bg-slate-800'}`}>
            {item}
          </button>
        ))}
      </nav>
      {error && <p role="alert" className="rounded-lg border border-rose-500/30 bg-rose-950/30 p-3 text-xs text-rose-200">{error}</p>}

      {section === 'Incidents' && (
        <div className="grid gap-4 xl:grid-cols-2">
          <div className="space-y-3">
            <label className="block text-xs text-slate-300">Incident
              <select value={activeIncidentId} onChange={(event) => selectIncident(event.target.value)} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2 text-sm text-white">
                <option value="">Select an incident</option>
                {incidents.map((incident) => <option key={incident.database_id} value={incident.database_id}>{incident.id} · {incident.category} · {incident.riskLevel}</option>)}
              </select>
            </label>
            <button type="button" disabled={busy || !activeIncidentId} onClick={() => loadIncidentContext(activeIncidentId)} className="rounded-lg border border-cyan-500/30 px-3 py-2 text-xs font-semibold text-cyan-200 disabled:opacity-50">Load timeline and memory</button>
            <form onSubmit={addComment} className="flex gap-2">
              <input value={comment} onChange={(event) => setComment(event.target.value)} maxLength={2000} placeholder="Add an analyst note" className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-white" />
              <button disabled={busy || !activeIncidentId || !comment.trim()} className="rounded-lg bg-cyan-700 px-3 py-2 text-xs font-semibold text-white disabled:opacity-50">Save note</button>
            </form>
            <div className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Incident timeline</h3>
              {timeline.length ? timeline.map((event, index) => <article key={`${event.timestamp}-${index}`} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3"><p className="text-xs font-semibold text-slate-200">{event.label || event.type}</p><p className="mt-1 text-[11px] text-slate-400">{event.detail || 'Recorded incident event'}</p><time className="mt-1 block text-[10px] text-slate-500">{event.timestamp}</time></article>) : <p className="text-xs text-slate-500">{busy ? 'Loading timeline…' : 'No timeline events recorded.'}</p>}
            </div>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Immune memory match</h3>
            <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-words text-[11px] text-slate-300">{memory ? JSON.stringify(memory, null, 2) : 'Select an incident to retrieve prior resolved patterns.'}</pre>
          </div>
        </div>
      )}

      {section === 'Campaigns' && (
        <div className="grid gap-3 md:grid-cols-2">
          <div className="space-y-2">{campaigns.map((campaign) => <button key={campaign.campaign_id} type="button" onClick={async () => { try { const response = await axios.get(`${apiBaseUrl}/api/v1/campaigns/${encodeURIComponent(campaign.campaign_id)}`, { headers }); setSelectedCampaign(response.data); } catch (requestError) { setError(requestError.response?.data?.detail || 'Campaign details unavailable.'); } }} className="w-full rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-left text-xs text-slate-200"><strong>{campaign.campaign_id}</strong><span className="float-right text-cyan-300">{campaign.incident_count} incidents</span><p className="mt-1 text-slate-400">{campaign.stage} · {campaign.confidence}% confidence</p></button>)}{!campaigns.length && <p className="text-xs text-slate-500">No correlated campaigns are available yet.</p>}</div>
          <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-slate-800 bg-slate-900/50 p-4 text-[11px] text-slate-300">{selectedCampaign ? JSON.stringify(selectedCampaign, null, 2) : 'Select a campaign to inspect linked incidents.'}</pre>
        </div>
      )}

      {section === 'Playbooks' && (
        <div className="grid gap-4 md:grid-cols-2">
          <div className="space-y-3">
            <label className="block text-xs text-slate-300">Incident
              <select value={activeIncidentId} onChange={(event) => selectIncident(event.target.value)} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2 text-sm text-white"><option value="">Select an incident</option>{incidents.map((incident) => <option key={incident.database_id} value={incident.database_id}>{incident.id} · {incident.category} · {incident.riskLevel}</option>)}</select>
            </label>
            <label className="block text-xs text-slate-300">Playbook
              <select value={selectedPlaybook} onChange={(event) => setSelectedPlaybook(event.target.value)} className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-900 p-2 text-sm text-white"><option value="">Select a playbook</option>{playbooks.map((playbook) => <option key={playbook.id} value={playbook.id}>{playbook.name}</option>)}</select>
            </label>
            <button type="button" disabled={busy} onClick={previewPlaybook} className="rounded-lg border border-amber-400/40 bg-amber-500/10 px-3 py-2 text-xs font-semibold text-amber-200 disabled:opacity-50">Create approval-gated plan</button>
            <p className="text-[11px] text-slate-500">Plans are dry-run previews. This workspace does not execute containment actions.</p>
          </div>
          <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-slate-800 bg-slate-900/50 p-4 text-[11px] text-slate-300">{plan ? JSON.stringify(plan, null, 2) : 'A plan will show its matching trigger, required approval, and proposed actions here.'}</pre>
        </div>
      )}

      {section === 'IOC lookup' && (
        <div className="space-y-3">
          <form onSubmit={lookupIoc} className="flex flex-col gap-2 sm:flex-row"><input value={ioc} onChange={(event) => setIoc(event.target.value)} maxLength={2048} placeholder="Domain, URL, IP address, or email" className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white" /><button disabled={busy || !ioc.trim()} className="rounded-lg bg-cyan-700 px-4 py-2 text-xs font-semibold text-white disabled:opacity-50">Look up indicator</button></form>
          <p className="text-[11px] text-slate-500">This result uses local heuristic enrichment unless a configured provider is available.</p>
          {iocResults && <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-slate-800 bg-slate-900/50 p-4 text-[11px] text-slate-300">{JSON.stringify(iocResults, null, 2)}</pre>}
        </div>
      )}
    </section>
  );
}
