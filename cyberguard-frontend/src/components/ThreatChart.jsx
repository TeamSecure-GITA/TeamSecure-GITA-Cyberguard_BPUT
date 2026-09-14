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

// Mock timeline data for security events over a 24-hour window
const timelineData = [
  { time: '00:00', Safe: 420, Low: 30, Medium: 15, High: 8, Critical: 2 },
  { time: '04:00', Safe: 380, Low: 25, Medium: 10, High: 5, Critical: 1 },
  { time: '08:00', Safe: 650, Low: 80, Medium: 45, High: 22, Critical: 7 },
  { time: '12:00', Safe: 920, Low: 110, Medium: 65, High: 35, Critical: 14 },
  { time: '16:00', Safe: 850, Low: 95, Medium: 50, High: 28, Critical: 9 },
  { time: '20:00', Safe: 540, Low: 60, Medium: 30, High: 12, Critical: 4 },
];

export default function ThreatChart({ timeline = [] }) {
  const chartData = timeline.length ? timeline : timelineData;
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
        <ResponsiveContainer width="100%" height="100%">
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
        </ResponsiveContainer>
      </div>
    </div>
  );
}