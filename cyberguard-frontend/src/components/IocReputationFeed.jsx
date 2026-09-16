import React, { useEffect, useState } from 'react';
import axios from 'axios';

export default function IocReputationFeed({ apiBaseUrl, accessToken }) {
  const [items, setItems] = useState([]);
  useEffect(() => {
    axios.get(`${apiBaseUrl}/api/v1/threat-intel/feed`, { headers: { Authorization: `Bearer ${accessToken}` } })
      .then((response) => setItems(response.data.items || [])).catch(() => setItems([]));
  }, [apiBaseUrl, accessToken]);
  return <section className="glass-panel p-5"><div className="panel-heading"><div><div className="eyebrow">IOC reputation feed</div><h3>Recent indicators</h3></div><span className="text-xs text-slate-500">local engine</span></div><div className="mt-4 space-y-2">{items.length ? items.slice(0, 6).map((item, index) => <div key={`${item.value}-${index}`} className="flex items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/70 border border-slate-800"><div className="min-w-0"><p className="text-xs text-slate-200 truncate">{item.value}</p><p className="text-[10px] text-slate-500">{item.type} / {item.reason}</p></div><span className={item.risk_score >= 70 ? 'text-rose-300' : item.risk_score >= 45 ? 'text-amber-300' : 'text-emerald-300'}>{item.reputation}</span></div>) : <p className="text-xs text-slate-500">No indicators available yet.</p>}</div></section>;
}
