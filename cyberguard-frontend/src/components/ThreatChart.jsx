import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

export default function ThreatChart({ timeline = [] }) {
  const chartData = timeline;
  return (
    <div className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg mb-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-bold text-white">Attack Timeline & Event Velocity</h3>
          <p className="text-xs text-slate-400">
            Real-time multi-source threat distribution by risk severity
          </p>
        </div>
        <div className="flex items-center space-x-3 text-xs">
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>Safe</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span>Low</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>Medium</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-orange-500"></span>High</span>
          <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500"></span>Critical</span>
        </div>
      </div>

      <div className="h-72 w-full">
        {chartData.length === 0 ? (
          <div className="h-full flex items-center justify-center rounded-lg border border-dashed border-slate-700 text-sm text-slate-400">
            No incident timeline data is available yet.
          </div>
        ) : <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f97316" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#f97316" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="time" stroke="#94a3b8" tick={{ fill: '#94a3b8', fontSize: 12 }} />
            <YAxis stroke="#94a3b8" tick={{ fill: '#94a3b8', fontSize: 12 }} />
            <Tooltip
              contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#f8fafc' }}
            />
            <Area type="monotone" dataKey="Critical" stroke="#ef4444" fillOpacity={1} fill="url(#colorCritical)" />
            <Area type="monotone" dataKey="High" stroke="#f97316" fillOpacity={1} fill="url(#colorHigh)" />
            <Area type="monotone" dataKey="Medium" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.1} />
            <Area type="monotone" dataKey="Low" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.1} />
            <Area type="monotone" dataKey="Safe" stroke="#10b981" fill="#10b981" fillOpacity={0.05} />
          </AreaChart>
        </ResponsiveContainer>}
      </div>
    </div>
  );
}