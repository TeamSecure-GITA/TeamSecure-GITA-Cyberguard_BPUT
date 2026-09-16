import React, { useEffect, useState } from 'react';
import axios from 'axios';

export default function IdentityRiskHeatmap({ apiBaseUrl, accessToken }) {
  const [identities, setIdentities] = useState([]);
  useEffect(() => {
    axios.get(`${apiBaseUrl}/api/v1/identity-risk`, { headers: { Authorization: `Bearer ${accessToken}` } })
      .then((response) => setIdentities(response.data.identities || [])).catch(() => setIdentities([]));
  }, [apiBaseUrl, accessToken]);
  return <section className="glass-panel p-5"><div className="panel-heading"><div><div className="eyebrow">Identity risk heatmap</div><h3>University user exposure</h3></div></div><div className="mt-4 space-y-3">{identities.map((identity) => <div key={identity.label}><div className="flex justify-between text-xs"><span>{identity.label}</span><strong className={identity.risk >= 75 ? 'text-rose-300' : identity.risk >= 45 ? 'text-amber-300' : 'text-emerald-300'}>{identity.risk}%</strong></div><div className="h-2 mt-1 rounded bg-slate-800"><div className="h-2 rounded bg-gradient-to-r from-emerald-400 via-amber-300 to-rose-400" style={{ width: `${identity.risk}%` }} /></div></div>)}</div></section>;
}
