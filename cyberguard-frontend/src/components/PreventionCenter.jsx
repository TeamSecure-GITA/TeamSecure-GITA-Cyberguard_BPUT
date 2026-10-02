import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { getApiBaseUrl } from '../apiConfig';

const apiBaseUrl = getApiBaseUrl();

export default function PreventionCenter({ accessToken }) {
  const [result, setResult] = useState(null);

  useEffect(() => {
    if (!accessToken) return;
    let active = true;
    const headers = { Authorization: `Bearer ${accessToken}` };

    const loadDecision = async () => {
      try {
        const incidentResponse = await axios.get(`${apiBaseUrl}/api/v1/incidents`, { headers });
        const incidents = incidentResponse.data.incidents || [];
        if (!incidents.length) {
          if (active) setResult({ accessToken, empty: true });
          return;
        }
        const incident = incidents[0];
        const decisionResponse = await axios.post(
          `${apiBaseUrl}/api/v1/prevention/decision`,
          { category: incident.category, payload: incident.payload, risk_score: incident.risk_score },
          { headers },
        );
        if (active) setResult({ accessToken, data: { ...decisionResponse.data, incident_id: incident.id } });
      } catch (requestError) {
        if (active) setResult({ accessToken, error: requestError.response?.data?.detail || 'Prevention service unavailable.' });
      }
    };

    loadDecision();
    return () => { active = false; };
  }, [accessToken]);

  if (!accessToken) return <section className="bg-cardBg border border-red-500/30 rounded-xl p-5 text-xs text-red-300">Authentication required.</section>;
  const currentResult = result?.accessToken === accessToken ? result : null;
  if (currentResult?.error) return <section className="bg-cardBg border border-red-500/30 rounded-xl p-5 text-xs text-red-300">{currentResult.error}</section>;

  if (!currentResult) {
    return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">Loading prevention decision...</section>;
  }

  if (currentResult.empty) return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">No stored incidents to evaluate yet.</section>;
  if (!currentResult.data) return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">Prevention decision unavailable.</section>;
  const { data } = currentResult;

  return (
    <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg">
      <p className="eyebrow">Prevention layer</p>
      <h2 className="text-xl font-bold text-white mt-1">Risk-Aware Prevention Engine</h2>
      <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-3">
          <div className="text-slate-400">Decision</div>
          <div className="mt-2 text-lg font-bold text-cyan-300 uppercase">{data.action}</div>
        </div>
        <div className="rounded-lg border border-slate-700 bg-slate-900/40 p-3">
          <div className="text-slate-400">Score</div>
          <div className="mt-2 text-lg font-bold text-white">{data.score}</div>
        </div>
        <div className="rounded-lg border border-slate-700 bg-slate-900/40 p-3">
          <div className="text-slate-400">Confidence</div>
          <div className="mt-2 text-lg font-bold text-white">{data.confidence}</div>
        </div>
      </div>
      <div className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-200">
        <div className="font-bold uppercase mb-1">Recommended response</div>
        <div>{data.recommended_response}</div>
      </div>
      <div className="mt-3 text-[11px] text-slate-400">
        Incident: {data.incident_id} · Triggered by: {data.category} · Reason: {data.reason} · {data.mode.replaceAll('_', ' ')}
      </div>
    </section>
  );
}
