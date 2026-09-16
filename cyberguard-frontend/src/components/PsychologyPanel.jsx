import React from 'react';

export default function PsychologyPanel({ psychology }) {
  const score = psychology?.manipulation_score || 0;
  return <section className="glass-panel p-5" aria-label="Human manipulation analysis">
    <div className="panel-heading"><div><div className="eyebrow">Human manipulation detector</div><h3>Psychology signal map</h3></div><strong className="text-amber-300">{score}%</strong></div>
    <div className="risk-meter-track mt-4"><div className="risk-meter-fill" style={{ width: `${score}%`, background: '#f6c76c' }} /></div>
    <div className="psychology-grid mt-3">{(psychology?.tactics || []).map((tactic) => <div className={tactic.detected ? 'psychology-hit' : ''} key={tactic.name}><span>{tactic.name}</span><b>{tactic.detected ? 'detected' : 'clear'}</b></div>)}</div>
  </section>;
}
