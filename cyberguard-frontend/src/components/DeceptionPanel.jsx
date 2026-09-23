import React, { useEffect, useState } from 'react';
import axios from 'axios';

const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function DeceptionPanel({ accessToken }) {
  const [status, setStatus] = useState(null);

  useEffect(() => {
    if (!accessToken) return;
    axios.get(`${apiBaseUrl}/api/v1/prevention/deception-status`, { headers: { Authorization: `Bearer ${accessToken}` } })
      .then((response) => setStatus(response.data))
      .catch(() => setStatus(null));
  }, [accessToken]);

  if (!status) return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">Deception status unavailable.</section>;

  return (
    <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg">
      <p className="eyebrow">Deception layer</p>
      <h2 className="text-xl font-bold text-white mt-1">Honeytoken & Decoy Monitoring</h2>
      <div className="mt-4 space-y-2 text-xs text-slate-300">
        <div>Active decoys: {status.active_decoys.length}</div>
        <div>Triggered decoys: {status.triggered_decoys.length}</div>
        <div>Compromised assets: {status.compromised_assets.join(', ') || 'none'}</div>
      </div>
    </section>
  );
}
