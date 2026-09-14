import React from 'react';
import { Activity, ArrowUpRight, Clock3, Radio } from 'lucide-react';

const severityClass = {
  Critical: 'feed-critical',
  High: 'feed-high',
  Medium: 'feed-medium',
  Low: 'feed-low',
};

export default function ThreatFeed({ incidents = [], onSelectIncident }) {
  const feed = incidents.slice(0, 5);

  return (
    <section className="glass-panel threat-feed">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Live telemetry / event stream</p>
          <h3>Threat Feed</h3>
        </div>
        <span className="feed-live"><Radio size={13} /> LIVE</span>
      </div>
      <div className="feed-list">
        {feed.map((incident, index) => (
          <button key={incident.id} type="button" className="feed-item" onClick={() => onSelectIncident?.(incident)}>
            <span className={`feed-severity ${severityClass[incident.riskLevel] || 'feed-low'}`} />
            <span className="feed-icon"><Activity size={15} /></span>
            <span className="feed-copy">
              <strong>{incident.category}</strong>
              <span>{incident.source} · {incident.id}</span>
            </span>
            <span className="feed-time"><Clock3 size={12} />{index === 0 ? 'now' : `${index * 4}m`}</span>
            <ArrowUpRight size={14} className="feed-arrow" />
          </button>
        ))}
        {!feed.length && <div className="feed-empty">Waiting for the first analyzed event.</div>}
      </div>
    </section>
  );
}
