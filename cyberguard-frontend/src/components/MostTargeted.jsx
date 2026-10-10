import React from 'react';
import { Globe2, Network, UserRound } from 'lucide-react';

const targetIcons = {
  service: Globe2,
  user: UserRound,
  network: Network,
};

export default function MostTargeted({ targets = [] }) {
  return (
    <section className="rounded-xl border border-slate-700/60 bg-cardBg p-4" aria-label="Frequently targeted entities">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div>
          <p className="eyebrow">Incident correlation</p>
          <h3 className="text-sm font-bold text-slate-100">Frequently targeted</h3>
        </div>
        <span className="text-[10px] text-slate-400">Latest 500 incidents</span>
      </div>
      {targets.length ? (
        <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {targets.slice(0, 8).map((target) => {
            const Icon = targetIcons[target.type] || Globe2;
            return (
              <li key={`${target.type}:${target.label}`} className="flex min-w-0 items-center gap-3 rounded-lg border border-slate-700/50 px-3 py-2">
                <Icon size={16} className="shrink-0 text-cyan-300" aria-hidden="true" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-xs font-medium text-slate-100" title={target.label}>{target.label}</div>
                  <div className="text-[10px] text-slate-400">{target.type} · {target.incident_count} incidents</div>
                </div>
                <span className="shrink-0 text-[10px] text-rose-300">risk {target.max_risk_score}/99</span>
              </li>
            );
          })}
        </ul>
      ) : (
        <p className="py-3 text-xs text-slate-400">No recurring users, services, or source networks found.</p>
      )}
    </section>
  );
}
