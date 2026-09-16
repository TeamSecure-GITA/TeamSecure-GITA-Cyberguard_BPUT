import React, { useEffect, useState } from 'react';
import axios from 'axios';

export default function ThreatMap({ apiBaseUrl, accessToken }) {
  const [data, setData] = useState({ locations: [], total_events: 0 });
  useEffect(() => {
    axios.get(`${apiBaseUrl}/api/v1/threat-map`, { headers: { Authorization: `Bearer ${accessToken}` } })
      .then((response) => setData(response.data)).catch(() => setData({ locations: [], total_events: 0 }));
  }, [apiBaseUrl, accessToken]);
  return <section className="glass-panel p-5">
    <div className="panel-heading"><div><div className="eyebrow">Live global threat map</div><h3>Distributed attack signals</h3></div><span className="text-xs text-cyan-300">{data.total_events} events</span></div>
    <div className="mt-4 grid grid-cols-2 gap-3">
      {data.locations.map((location) => <div key={location.code} className="p-3 rounded-xl bg-slate-900/70 border border-slate-800"><div className="flex justify-between text-xs"><strong>{location.country}</strong><span className="text-cyan-300">{location.count}</span></div><p className="text-[11px] text-slate-400 mt-1">{location.category}</p><div className="h-1 mt-2 rounded bg-slate-800"><div className="h-1 rounded bg-cyan-400" style={{ width: `${Math.min(100, location.count * 12)}%` }} /></div></div>)}
    </div>
  </section>;
}
