import React from 'react';
import { Activity, Cpu, HardDrive, CheckCircle2 } from 'lucide-react';

export default function SystemHealth({ health }) {
  return (
    <div className="health-grid grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
      <div className="health-card">
        <Activity className="text-cyan-400" size={24} />
        <div>
          <p className="text-[10px] text-slate-400 uppercase font-bold">API Latency</p>
          <p className="text-sm font-bold text-white">{health ? `${health.api_latency_ms ?? 0} ms` : 'Checking...'}</p>
        </div>
      </div>
      <div className="health-card">
        <Cpu className="text-emerald-400" size={24} />
        <div>
          <p className="text-[10px] text-slate-400 uppercase font-bold">Model Confidence</p>
          <p className="text-sm font-bold text-white">{health ? (health.model_loaded ? (health.model_confidence || 'Loaded') : 'Heuristics active') : 'Checking...'}</p>
        </div>
      </div>
      <div className="health-card">
        <HardDrive className="text-purple-400" size={24} />
        <div>
          <p className="text-[10px] text-slate-400 uppercase font-bold">Engine Throughput</p>
          <p className="text-sm font-bold text-white">{health ? `${health.events_per_minute ?? 0}/min` : 'Checking...'}</p>
        </div>
      </div>
      <div className="health-card">
        <CheckCircle2 className="text-blue-400" size={24} />
        <div>
          <p className="text-[10px] text-slate-400 uppercase font-bold">Threat Accuracy</p>
          <p className="text-sm font-bold text-white">{health?.status === 'healthy' ? `${health.threat_accuracy ?? 0}% F1` : 'Checking...'}</p>
        </div>
      </div>
    </div>
  );
}