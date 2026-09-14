import React from 'react';
import { AlertCircle, ArrowUpRight, GitFork, Link2, ShieldAlert } from 'lucide-react';

export default function CampaignCorrelation({ correlations, onSelectIncident }) {
  if (!correlations) {
    return (
      <div className="p-6 text-center text-xs text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
        <Link2 className="mx-auto mb-2 opacity-40 text-cyan-400 animate-pulse" size={24} />
        Scanning for cross-incident campaign indicators...
      </div>
    );
  }

  const confidence = correlations.confidence || 0;
  const isHighConfidence = confidence >= 70;

  return (
    <div className="space-y-4">
      {/* Campaign Banner */}
      <div className="p-4 bg-gradient-to-r from-slate-900 via-indigo-950/30 to-slate-900 rounded-xl border border-indigo-500/30 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
            <GitFork size={20} />
          </div>
          <div>
            <div className="text-[10px] text-indigo-400 font-bold tracking-wider uppercase">Active Campaign Cluster</div>
            <div className="font-mono text-base font-black text-white tracking-wider flex items-center gap-2">
              {correlations.campaign_id || 'STANDALONE-THREAT'}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="text-right">
            <span className="text-[10px] text-slate-400 uppercase font-semibold">Cluster Confidence</span>
            <div className={`text-sm font-bold ${isHighConfidence ? 'text-emerald-400' : 'text-amber-400'}`}>
              {confidence}% Confidence
            </div>
          </div>

          <div className="px-3 py-1.5 rounded-lg bg-indigo-500/20 border border-indigo-500/40 text-xs font-semibold text-indigo-200">
            {correlations.stage || 'Discovery'}
          </div>
        </div>
      </div>

      {/* Correlated Incidents List */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-[11px] font-semibold text-slate-400 px-1">
          <span>Linked Incidents ({correlations.related_incidents?.length || 0})</span>
          <span>Vector Overlap</span>
        </div>

        {(correlations.related_incidents || []).length > 0 ? (
          <div className="space-y-2">
            {correlations.related_incidents.map((match) => (
              <div
                key={match.incident_id}
                className="flex items-center justify-between p-3 bg-slate-900/60 hover:bg-slate-800/60 rounded-xl border border-slate-800 transition"
              >
                <div className="flex items-center gap-3">
                  <div className="font-mono text-xs font-bold text-cyan-400">
                    INC-{String(match.incident_id).padStart(4, '0')}
                  </div>
                  <div className="text-xs text-slate-300">
                    {match.reason || 'Shared attack vector and IOC profile'}
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded-md bg-cyan-500/10 border border-cyan-500/25 text-xs font-bold text-cyan-300">
                    {match.score}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-4 text-center text-xs text-slate-500 bg-slate-900/20 rounded-xl border border-slate-800/60">
            No related incidents identified in the correlation window. Threat isolated.
          </div>
        )}
      </div>
    </div>
  );
}
