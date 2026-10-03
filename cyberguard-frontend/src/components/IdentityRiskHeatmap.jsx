import React, { useEffect, useState } from 'react';
import axios from 'axios';

export default function IdentityRiskHeatmap({ apiBaseUrl, accessToken }) {
  const [identities, setIdentities] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    axios.get(`${apiBaseUrl}/api/v1/identity-risk`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
      .then((response) => {
        setIdentities(response.data.identities || []);
        setError('');
      })
      .catch((requestError) => {
        setIdentities([]);
        setError(requestError.response?.data?.detail || requestError.message || 'Identity risk data could not be loaded.');
      });
  }, [apiBaseUrl, accessToken]);

  return (
    <section className="glass-panel p-5">
      <div className="panel-heading">
        <div><div className="eyebrow">Identity risk heatmap</div><h3>Observed email exposure</h3></div>
      </div>
      <p className="mt-2 text-[10px] text-slate-500">
        Average incident risk for masked email addresses found in analyzed payloads.
      </p>
      {error && <p role="alert" className="mt-3 text-xs text-rose-300">{error}</p>}
      {!error && identities.length === 0 && (
        <p className="mt-4 text-xs text-slate-400">No incident email identities are available to score.</p>
      )}
      <div className="mt-4 space-y-3">
        {identities.map((identity) => (
          <div key={identity.label}>
            <div className="flex justify-between text-xs">
              <span>{identity.label} · {identity.incidents} incident{identity.incidents === 1 ? '' : 's'}</span>
              <strong className={identity.risk >= 75 ? 'text-rose-300' : identity.risk >= 45 ? 'text-amber-300' : 'text-emerald-300'}>
                {identity.risk}%
              </strong>
            </div>
            <div className="h-2 mt-1 rounded bg-slate-800">
              <div
                className="h-2 rounded bg-gradient-to-r from-emerald-400 via-amber-300 to-rose-400"
                style={{ width: `${identity.risk}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
