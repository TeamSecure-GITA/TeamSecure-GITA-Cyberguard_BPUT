import React from 'react';

export default function SelfHealingPanel({ healing }) {
  return <section className="glass-panel p-5" aria-label="Self-healing network recommendations">
    <div className="panel-heading"><div><div className="eyebrow">Self-healing network</div><h3>Recovery sequence</h3></div><strong className="text-amber-300">{healing?.priority || 'normal'}</strong></div>
    <div className="intel-list mt-4">{(healing?.actions || []).map((action) => <div className="intel-row" key={action.order}><span>{String(action.order).padStart(2, '0')}</span><small>{action.label}</small><b>ready</b></div>)}{!healing?.actions?.length && <p className="text-xs text-slate-500">Awaiting recovery recommendations.</p>}</div>
  </section>;
}
