import React, { useEffect, useState } from 'react';
import axios from 'axios';

const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function PolicyEnginePanel({ accessToken }) {
  const [policies, setPolicies] = useState(null);

  useEffect(() => {
    if (!accessToken) return;
    axios.get(`${apiBaseUrl}/api/v1/prevention/policies`, { headers: { Authorization: `Bearer ${accessToken}` } })
      .then((response) => setPolicies(response.data))
      .catch(() => setPolicies(null));
  }, [accessToken]);

  if (!policies) return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 text-xs text-slate-300">Policy engine unavailable.</section>;

  return (
    <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg">
      <p className="eyebrow">Policy engine</p>
      <h2 className="text-xl font-bold text-white mt-1">Adaptive Prevention Policies</h2>
      <div className="mt-4 rounded-lg border border-violet-500/25 bg-violet-500/5 p-3 text-xs text-violet-100">
        <div>Enforcement level: {policies.enforcement_level}</div>
        <div className="mt-2">Department profile: {policies.department_profile}</div>
      </div>
      <div className="mt-3 text-xs text-slate-300">Rules: {policies.policy_rules.join(', ')}</div>
    </section>
  );
}
