import React, { useEffect, useState } from 'react';
import axios from 'axios';

const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function InsiderRiskPanel({ accessToken }) {
  const [risk, setRisk] = useState(null);

  useEffect(() => {
    if (!accessToken) return;
    axios.get(`${apiBaseUrl}/api/v1/prevention/insider-risk`, { headers: { Authorization: `Bearer ${accessToken}` } })
      .then((response) => setRisk(response.data))
      .catch(() => setRisk(null));
  }, [accessToken]);

  if (!risk) return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">Insider risk unavailable.</section>;

  return (
    <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg">
      <p className="eyebrow">Insider prevention</p>
      <h2 className="text-xl font-bold text-white mt-1">Insider Threat Risk</h2>
      <div className="mt-4 rounded-lg border border-red-500/25 bg-red-500/5 p-3 text-xs text-red-100">
        <div>Risk score: {risk.risk_score}</div>
        <div className="mt-2">Preventive action: {risk.preventive_action}</div>
      </div>
      <div className="mt-3 text-xs text-slate-300">Flags: {Object.entries(risk.flags).filter(([, value]) => value).map(([key]) => key).join(', ') || 'none'}</div>
    </section>
  );
}
