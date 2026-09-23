import React, { useEffect, useState } from 'react';
import axios from 'axios';

const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function ContainmentQueue({ accessToken }) {
  const [queue, setQueue] = useState(null);

  useEffect(() => {
    if (!accessToken) return;
    axios.post(
      `${apiBaseUrl}/api/v1/prevention/containment`,
      { incident_id: 'INC-101', risk_score: 90, source_ip: '198.51.100.10', category: 'email' },
      { headers: { Authorization: `Bearer ${accessToken}` } },
    ).then((response) => setQueue(response.data)).catch(() => setQueue(null));
  }, [accessToken]);

  if (!queue) return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">Containment queue not available.</section>;

  return (
    <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg">
      <p className="eyebrow">Containment</p>
      <h2 className="text-xl font-bold text-white mt-1">Containment Queue</h2>
      <div className="mt-4 rounded-lg border border-amber-500/25 bg-amber-500/5 p-3 text-xs text-amber-100">
        <div>Priority: {queue.priority}</div>
        <div className="mt-2">Source IP: {queue.source_ip}</div>
      </div>
      <div className="mt-4 text-xs text-slate-300">Actions: {queue.actions.join(', ')}</div>
    </section>
  );
}
