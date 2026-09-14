import React, { useState } from 'react';
import { ArrowDown, Check, Loader2, Play, ShieldAlert, Sparkles } from 'lucide-react';
import axios from 'axios';

const AVAILABLE_ACTIONS = [
  { id: 'isolate', label: 'Isolate Host Endpoint', reduction: 28, desc: 'Cut network connectivity' },
  { id: 'revoke', label: 'Revoke Token & Force MFA', reduction: 20, desc: 'Invalidate active sessions' },
  { id: 'block', label: 'Block Malicious IOC', reduction: 18, desc: 'Firewall & DNS blackhole' },
  { id: 'notify', label: 'Notify Target Users', reduction: 8, desc: 'Security alert push' },
];

export default function ResponseSimulatorPanel({ incident, accessToken, apiBaseUrl = 'http://127.0.0.1:8000' }) {
  const [selectedActions, setSelectedActions] = useState(['isolate', 'revoke']);
  const [simulation, setSimulation] = useState(null);
  const [loading, setLoading] = useState(false);

  const toggleAction = (id) => {
    setSelectedActions((prev) =>
      prev.includes(id) ? prev.filter((a) => a !== id) : [...prev, id]
    );
  };

  const handleSimulate = async () => {
    if (!incident?.database_id) return;
    setLoading(true);
    try {
      const config = { headers: { Authorization: `Bearer ${accessToken}` } };
      const res = await axios.post(
        `${apiBaseUrl}/api/v1/incidents/${incident.database_id}/simulate`,
        { actions: selectedActions },
        config
      );
      setSimulation(res.data);
    } catch (e) {
      console.error('Simulation error', e);
    } finally {
      setLoading(false);
    }
  };

  const currentRisk = incident?.riskScore || 85;
  const projectedRisk = simulation ? simulation.projected_risk : Math.max(0, currentRisk - selectedActions.reduce((acc, curr) => acc + (AVAILABLE_ACTIONS.find(a => a.id === curr)?.reduction || 0), 0));
  const reduction = currentRisk - projectedRisk;

  return (
    <div className="space-y-4">
      {/* Action Selector Chips */}
      <div>
        <label className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider block mb-2">
          Select Candidate Containment Controls
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {AVAILABLE_ACTIONS.map((action) => {
            const isSelected = selectedActions.includes(action.id);
            return (
              <button
                key={action.id}
                type="button"
                onClick={() => toggleAction(action.id)}
                className={`p-2.5 rounded-xl border text-left transition flex items-center justify-between ${
                  isSelected
                    ? 'bg-cyan-500/10 border-cyan-500/40 text-slate-100 shadow-[0_0_10px_rgba(6,182,212,0.1)]'
                    : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:bg-slate-800/60'
                }`}
              >
                <div>
                  <div className="text-xs font-bold">{action.label}</div>
                  <div className="text-[10px] text-slate-400">{action.desc}</div>
                </div>
                <div className="text-right">
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${isSelected ? 'bg-cyan-500/20 text-cyan-300' : 'bg-slate-800 text-slate-400'}`}>
                    -{action.reduction}%
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Before / After Projection Meter */}
      <div className="p-4 bg-slate-900/80 rounded-xl border border-slate-800 flex items-center justify-between gap-4">
        <div>
          <span className="text-[10px] text-slate-400 uppercase font-semibold">Current Risk</span>
          <div className="text-xl font-black text-rose-400">{currentRisk}%</div>
        </div>

        <div className="flex flex-col items-center">
          <span className="text-[10px] text-cyan-400 font-bold uppercase mb-1">Impact</span>
          <div className="flex items-center gap-1 text-emerald-400 text-xs font-bold px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20">
            <ArrowDown size={12} /> -{reduction}%
          </div>
        </div>

        <div className="text-right">
          <span className="text-[10px] text-slate-400 uppercase font-semibold">Projected Risk</span>
          <div className="text-xl font-black text-emerald-400">{projectedRisk}%</div>
        </div>
      </div>

      {/* Simulation Trigger Button */}
      <button
        type="button"
        onClick={handleSimulate}
        disabled={loading || selectedActions.length === 0}
        className="w-full py-2.5 px-4 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-40 text-white rounded-xl text-xs font-bold flex items-center justify-center gap-2 shadow-lg shadow-cyan-900/20 transition"
      >
        {loading ? (
          <>
            <Loader2 size={14} className="animate-spin" /> Simulating Mitigation Dynamics...
          </>
        ) : (
          <>
            <Play size={14} /> Run What-If Response Simulation
          </>
        )}
      </button>

      {simulation && (
        <div className="p-3 bg-emerald-950/20 border border-emerald-500/30 rounded-xl flex items-center justify-between text-xs">
          <span className="text-slate-300">
            Projected Outcome: <strong className="text-emerald-300 font-bold">{simulation.outcome}</strong>
          </span>
          <span className="text-[10px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded font-mono">
            {simulation.risk_reduction}% Total Mitigation
          </span>
        </div>
      )}
    </div>
  );
}
