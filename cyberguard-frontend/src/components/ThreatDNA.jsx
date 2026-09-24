import React, { useState } from 'react';
import { Check, Copy, Dna, Sparkles } from 'lucide-react';

export default function ThreatDNA({ genome, _incidentId }) {
  const [copied, setCopied] = useState(false);

  if (!genome) {
    return (
      <div className="p-6 text-center text-xs text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
        <Dna className="mx-auto mb-2 opacity-40 animate-pulse text-cyan-400" size={24} />
        Awaiting threat DNA sequencing for incident...
      </div>
    );
  }

  const handleCopy = () => {
    if (genome.fingerprint) {
      navigator.clipboard.writeText(genome.fingerprint);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const similarity = genome.similarity_score || 0;
  const matchColor = similarity >= 80 ? 'text-red-400 border-red-500/40 bg-red-500/10' :
                     similarity >= 50 ? 'text-amber-400 border-amber-500/40 bg-amber-500/10' :
                     'text-cyan-400 border-cyan-500/40 bg-cyan-500/10';

  return (
    <div className="space-y-4">
      {/* DNA Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-gradient-to-r from-slate-900/90 via-cyan-950/20 to-slate-900/90 rounded-xl border border-cyan-500/20">
        <div className="flex items-center gap-3">
          <div className="relative w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-300 font-mono font-bold text-sm shadow-[0_0_15px_rgba(6,182,212,0.15)]">
            <Dna size={22} className="animate-pulse" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-bold text-cyan-400 tracking-wider uppercase">Genome Fingerprint</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">SHA256:16</span>
            </div>
            <div className="font-mono text-base font-black text-slate-100 tracking-wider flex items-center gap-2 mt-0.5">
              <span>{genome.fingerprint}</span>
              <button
                type="button"
                onClick={handleCopy}
                className="p-1 text-slate-400 hover:text-cyan-300 transition rounded"
                title="Copy Threat Fingerprint"
              >
                {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
              </button>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <span className="text-[10px] text-slate-400 uppercase font-semibold">Heuristic Similarity</span>
            <div className={`px-2.5 py-1 rounded-full text-xs font-bold border ${matchColor} text-center mt-0.5`}>
              {similarity}% Match
            </div>
          </div>
        </div>
      </div>

      {/* Vector Matrix Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800">
          <span className="text-[10px] font-semibold text-slate-400 uppercase">Initial Access</span>
          <p className="text-xs font-bold text-slate-200 mt-1 capitalize truncate">
            {genome.vectors?.initial_access || 'Unknown'}
          </p>
        </div>

        <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800">
          <span className="text-[10px] font-semibold text-slate-400 uppercase">Signal Count</span>
          <p className="text-xs font-bold text-cyan-300 mt-1">
            {genome.vectors?.signals || 0} Indicators
          </p>
        </div>

        <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800 col-span-2">
          <span className="text-[10px] font-semibold text-slate-400 uppercase">IOC Signatures</span>
          <div className="flex flex-wrap gap-1 mt-1">
            {(genome.vectors?.ioc_types || []).length > 0 ? (
              genome.vectors.ioc_types.map((type) => (
                <span key={type} className="px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-[10px] font-mono text-cyan-300 uppercase">
                  {type}
                </span>
              ))
            ) : (
              <span className="text-[10px] text-slate-500 italic">No IOC types parsed</span>
            )}
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Techniques Mapped */}
      <div className="p-3.5 bg-slate-900/40 rounded-xl border border-slate-800">
        <div className="flex items-center gap-1.5 mb-2">
          <Sparkles size={12} className="text-amber-400" />
          <span className="text-[10px] font-bold text-slate-300 uppercase tracking-wider">MITRE ATT&CK Mapping</span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {(genome.vectors?.techniques || []).length > 0 ? (
            genome.vectors.techniques.map((tech) => (
              <span key={tech} className="px-2.5 py-1 rounded-md bg-amber-500/10 border border-amber-500/25 text-[11px] font-mono text-amber-300 font-semibold">
                {tech}
              </span>
            ))
          ) : (
            <span className="text-[11px] text-slate-500">No MITRE ATT&CK techniques associated.</span>
          )}
        </div>
      </div>
    </div>
  );
}
