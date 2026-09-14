import React from 'react';
import { ShieldAlert, Mail, Video, UserX, AlertTriangle, Activity } from 'lucide-react';

export default function MetricCards({ metrics }) {
  const cards = [
    {
      title: 'Total Threats',
      value: metrics ? metrics.totalEvents : '--',
      change: metrics ? 'All scored telemetry' : 'Waiting for API',
      icon: Activity,
      color: 'text-blue-400',
      borderColor: 'border-blue-500/30',
    },
    {
      title: 'Phishing',
      value: metrics ? metrics.phishingCount : '--',
      change: 'Email, SMS & URL events',
      icon: ShieldAlert,
      color: 'text-red-400',
      borderColor: 'border-red-500/30',
    },
    {
      title: 'Suspected Deepfakes',
      value: metrics ? metrics.deepfakeCount : '--',
      change: 'Media assessments',
      icon: Video,
      color: 'text-purple-400',
      borderColor: 'border-purple-500/30',
    },
    {
      title: 'ATO',
      value: metrics ? metrics.atoCount : '--',
      change: 'Authentication anomalies',
      icon: AlertTriangle,
      color: 'text-orange-400',
      borderColor: 'border-orange-500/30',
    },
    {
      title: 'Active Incidents',
      value: metrics ? metrics.activeIncidents : '--',
      change: 'Open response queue',
      icon: UserX,
      color: 'text-cyan-400',
      borderColor: 'border-cyan-500/30',
    },
    {
      title: 'Safe Requests',
      value: metrics ? metrics.safeRequests : '--',
      change: 'Cleared by the engine',
      icon: Mail,
      color: 'text-emerald-400',
      borderColor: 'border-emerald-500/30',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`bg-cardBg border ${card.borderColor} rounded-xl p-4 flex flex-col justify-between shadow-lg`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">{card.title}</span>
              <Icon className={card.color} size={20} />
            </div>
            <div className="mt-3">
              <h3 className="text-2xl font-bold text-white">{card.value}</h3>
              <p className="text-[10px] text-slate-400 mt-1">{card.change}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}