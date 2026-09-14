import React, { useEffect, useMemo, useState } from 'react';
import { AlertCircle, CheckCircle2, ChevronDown, Eye, Search, Terminal } from 'lucide-react';
import axios from 'axios';

const getSeverityBadge = (level) => {
  switch (level) {
    case 'Critical':
      return 'bg-red-500/20 text-red-400 border-red-500/40';
    case 'High':
      return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
    case 'Medium':
      return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
    case 'Low':
      return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
    default:
      return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
  }
};

export default function IncidentTable({ incidents = [], accessToken, onRefresh, onSelectIncident, initialSearch = '' }) {
  const [search, setSearch] = useState(initialSearch);
  const [status, setStatus] = useState('');
  const [saving, setSaving] = useState(null);
  const [expanded, setExpanded] = useState(null);
  useEffect(() => setSearch(initialSearch), [initialSearch]);
  const visibleIncidents = useMemo(() => incidents.filter((incident) => {
    const matchesSearch = !search || `${incident.id} ${incident.category} ${incident.source}`.toLowerCase().includes(search.toLowerCase());
    return matchesSearch && (!status || incident.status === status);
  }), [incidents, search, status]);

  const updateIncident = async (incident, nextStatus) => {
    setSaving(incident.database_id);
    try {
      await axios.patch(`http://127.0.0.1:8000/api/v1/incidents/${incident.database_id}`, { status: nextStatus }, { headers: { Authorization: `Bearer ${accessToken}` } });
      onRefresh?.();
    } finally {
      setSaving(null);
    }
  };
  return (
    <div className="bg-cardBg border border-slate-700/60 rounded-xl shadow-lg overflow-hidden">
      <div className="p-5 border-b border-slate-700 flex items-center justify-between">
        <div>
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <Terminal size={20} className="text-cyan-400" /> Live Threat Stream & Incident Response
          </h3>
          <p className="text-xs text-slate-400">
            Real-time automated detection, risk scoring, and XAI assessment
          </p>
        </div>
        <div className="incident-tools">
          <label className="incident-search"><Search size={13} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search incidents, IOC, URL..." /></label>
          <div className="flex items-center gap-2">
            <select value={status} onChange={(event) => setStatus(event.target.value)} className="bg-slate-950/60 border border-slate-700 rounded-md px-2 py-1 text-[10px] text-slate-300">
              <option value="">All statuses</option><option>New</option><option>Investigating</option><option>Contained</option><option>Mitigated</option><option>Closed</option>
            </select>
            <span className="text-[10px] text-slate-400">{visibleIncidents.length} events</span>
          </div>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-sm">
          <thead>
            <tr className="bg-slate-900/60 text-slate-400 text-xs border-b border-slate-700">
              <th className="p-4">Incident ID</th>
              <th className="p-4">Timestamp</th>
              <th className="p-4">Source / Entity</th>
              <th className="p-4">Target / Service</th>
              <th className="p-4">Threat Category</th>
              <th className="p-4">Risk Severity</th>
              <th className="p-4">Status</th>
              <th className="p-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {visibleIncidents.map((inc) => (
              <React.Fragment key={inc.id}><tr className="hover:bg-slate-800/40 transition-colors text-slate-200">
                <td className="p-4 font-mono text-cyan-400 font-semibold">{inc.id}</td>
                <td className="p-4 text-xs text-slate-400">{inc.timestamp}</td>
                <td className="p-4 font-mono text-xs text-slate-300 truncate max-w-[150px]">
                  {inc.source}
                </td>
                <td className="p-4 text-xs text-slate-400 truncate max-w-[150px]">
                  {inc.target}
                </td>
                <td className="p-4 text-xs font-medium">{inc.category}</td>
                <td className="p-4">
                  <span
                    className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${getSeverityBadge(
                      inc.riskLevel
                    )}`}
                  >
                    {inc.riskLevel} ({inc.riskScore}%)
                  </span>
                </td>
                <td className="p-4">
                  <span className="text-xs text-slate-300 flex items-center gap-1.5">
                    {inc.status === 'Mitigated' ? (
                      <CheckCircle2 size={14} className="text-emerald-400" />
                    ) : (
                      <AlertCircle size={14} className="text-amber-400" />
                    )}
                    <select value={inc.status} disabled={saving === inc.database_id} onChange={(event) => updateIncident(inc, event.target.value)} className="bg-transparent text-xs text-slate-300 focus:outline-none">
                      <option>New</option><option>Investigating</option><option>Contained</option><option>Mitigated</option><option>Closed</option>
                    </select>
                  </span>
                </td>
                <td className="p-4 text-right">
                  <button type="button"
                    onClick={() => setExpanded(expanded === inc.id ? null : inc.id)}
                    className="p-2 text-slate-400 hover:text-cyan-300 transition"
                    title="Expand incident details"
                  ><ChevronDown size={15} className={expanded === inc.id ? 'rotate-180 transition-transform' : 'transition-transform'} /></button><button
                    type="button"
                    onClick={() => onSelectIncident && onSelectIncident(inc)}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-cyan-600 text-slate-200 hover:text-white rounded-lg text-xs border border-slate-700 transition flex items-center gap-1.5 ml-auto"
                  >
                    <Eye size={14} /> Analyze XAI
                  </button>
                </td>
              </tr>{expanded === inc.id && <tr className="incident-expanded"><td colSpan="8"><div className="incident-detail-grid"><div><span>Why flagged</span><p>{inc.explanation || 'No explanation available.'}</p></div><div><span>Indicators</span><p>{(inc.indicators || []).map((item) => item.name).join(' · ') || 'No extracted indicators.'}</p></div><div><span>Response state</span><p>{inc.status} {inc.assigned_to ? `· assigned to ${inc.assigned_to}` : ''}</p></div></div></td></tr>}</React.Fragment>
            ))}
            {incidents.length === 0 && (
              <tr><td colSpan="8" className="p-8 text-center text-xs text-slate-500">No incidents stored yet. Run an inspection to create the first event.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}