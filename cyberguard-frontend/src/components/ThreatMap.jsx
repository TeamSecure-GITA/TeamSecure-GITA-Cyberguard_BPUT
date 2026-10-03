import React, { useEffect, useState } from 'react';
import axios from 'axios';

export default function ThreatMap({ apiBaseUrl, accessToken }) {
  const [data, setData] = useState({ locations: [], total_events: 0, geolocated_events: 0 });
  const [error, setError] = useState('');

  useEffect(() => {
    axios.get(`${apiBaseUrl}/api/v1/threat-map`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
      .then((response) => {
        setData(response.data);
        setError('');
      })
      .catch((requestError) => {
        setData({ locations: [], total_events: 0, geolocated_events: 0 });
        setError(requestError.response?.data?.detail || requestError.message || 'Threat map data could not be loaded.');
      });
  }, [apiBaseUrl, accessToken]);

  return (
    <section className="glass-panel p-5">
      <div className="panel-heading">
        <div><div className="eyebrow">Observed threat locations</div><h3>Geolocated incident data</h3></div>
        <span className="text-xs text-cyan-300">{data.geolocated_events} geolocated</span>
      </div>
      <p className="mt-2 text-[10px] text-slate-500">
        Locations use caller-reported, range-validated source metadata; verify it upstream before relying on it.
      </p>
      {error && <p role="alert" className="mt-3 text-xs text-rose-300">{error}</p>}
      {!error && data.locations.length === 0 && (
        <p className="mt-4 text-xs text-slate-400">
          No incident source locations are available. {data.total_events} events analyzed.
        </p>
      )}
      <div className="mt-4 grid grid-cols-2 gap-3">
        {data.locations.map((location) => (
          <div key={`${location.code}-${location.category}`} className="p-3 rounded-xl bg-slate-900/70 border border-slate-800">
            <div className="flex justify-between text-xs">
              <strong>{location.country}</strong>
              <span className="text-cyan-300">{location.count}</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">{location.category}</p>
            <div className="h-1 mt-2 rounded bg-slate-800">
              <div className="h-1 rounded bg-cyan-400" style={{ width: `${Math.min(100, location.count * 12)}%` }} />
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
