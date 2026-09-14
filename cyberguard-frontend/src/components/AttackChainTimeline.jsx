import React from 'react';
import { AlertCircle, CheckCircle2, Clock, GitCommit, Shield, ShieldCheck } from 'lucide-react';

export default function AttackChainTimeline({ timeline }) {
  if (!timeline || timeline.length === 0) {
    return (
      <div className="p-6 text-center text-xs text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
        <GitCommit className="mx-auto mb-2 opacity-40 text-cyan-400 animate-pulse" size={24} />
        Awaiting attack chain timeline reconstruction...
      </div>
    );
  }

  const getStatusBadge = (status) => {
    switch (status?.toLowerCase()) {
      case 'mitigated':
      case 'contained':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'detected':
      case 'flagged':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'blocked':
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
      default:
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
    }
  };

  return (
    <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-gradient-to-b before:from-cyan-500 before:via-indigo-500 before:to-slate-700">
      {timeline.map((event, idx) => (
        <div key={event.id || idx} className="relative group">
          {/* Timeline Node Dot */}
          <div className="absolute -left-[27px] top-1 w-5 h-5 rounded-full bg-slate-900 border-2 border-cyan-400 flex items-center justify-center shadow-[0_0_10px_rgba(6,182,212,0.4)]">
            <div className="w-1.5 h-1.5 rounded-full bg-cyan-300" />
          </div>

          {/* Event Content Card */}
          <div className="p-3.5 bg-slate-900/70 group-hover:bg-slate-800/70 rounded-xl border border-slate-800 transition">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-bold text-cyan-400 px-1.5 py-0.5 rounded bg-cyan-950/40 border border-cyan-800/40 uppercase">
                  {event.id}
                </span>
                <h4 className="text-xs font-bold text-slate-200">
                  {event.label}
                </h4>
              </div>

              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${getStatusBadge(event.status)}`}>
                  {event.status || 'DETECTED'}
                </span>
                <span className="text-[10px] text-slate-500 flex items-center gap-1">
                  <Clock size={11} />
                  {event.timestamp ? new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '--:--'}
                </span>
              </div>
            </div>

            <p className="text-xs text-slate-400 mt-1">
              {event.detail}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}
