import React, { useEffect, useState } from 'react';
import axios from 'axios';

const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function IdentityTrustPanel({ accessToken }) {
  const [trust, setTrust] = useState(null);

  useEffect(() => {
    if (!accessToken) return;
    axios.get(`${apiBaseUrl}/api/v1/prevention/identity-trust`, { headers: { Authorization: `Bearer ${accessToken}` } })
      .then((response) => setTrust(response.data))
      .catch(() => setTrust(null));
  }, [accessToken]);

  if (!trust) return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">Identity trust not available.</section>;

  return (
    <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg">
      <p className="eyebrow">Identity trust</p>
      <h2 className="text-xl font-bold text-white mt-1">Zero-Trust Identity Check</h2>
      <div className="mt-4 rounded-lg border border-cyan-500/25 bg-cyan-500/5 p-3 text-xs text-cyan-100">
        <div>Trust score: {trust.trust_score}</div>
        <div className="mt-2">Status: {trust.status}</div>
      </div>
      <div className="mt-3 text-xs text-slate-300">Required action: {trust.required_action}</div>
    </section>
  );
}
