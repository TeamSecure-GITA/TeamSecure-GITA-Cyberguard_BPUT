import React, { useEffect, useState } from 'react';
import axios from 'axios';

const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function PreventionCenter({ accessToken }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!accessToken) return;

    axios.post(
      `${apiBaseUrl}/api/v1/prevention/decision`,
      {
        category: 'email',
        payload: 'URGENT verify credentials at https://secure-login.example/auth',
        asset_criticality: 'critical',
        risk_score: 92,
        user: { role: 'admin', team: 'finance' },
      },
      { headers: { Authorization: `Bearer ${accessToken}` } },
    )
      .then((response) => setData(response.data))
      .catch((requestError) => setError(requestError.response?.data?.detail || 'Prevention service unavailable.'));
  }, [accessToken]);

  if (error) {
    return <section className="bg-cardBg border border-red-500/30 rounded-xl p-5 text-xs text-red-300">{error}</section>;
  }

  if (!data) {
    return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">Loading prevention decision...</section>;
  }

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
        Triggered by: {data.category} · Reason: {data.reason}
      </div>
    </section>
  );
}
