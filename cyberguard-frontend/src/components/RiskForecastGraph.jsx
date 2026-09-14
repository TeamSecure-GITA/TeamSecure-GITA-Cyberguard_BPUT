import React from 'react';
import { Activity, AlertTriangle, TrendingDown, TrendingUp } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

export default function RiskForecastGraph({ forecast }) {
  if (!forecast || !forecast.forecast || forecast.forecast.length === 0) {
    return (
      <div className="p-6 text-center text-xs text-slate-500 bg-slate-900/40 rounded-xl border border-slate-800">
        <Activity className="mx-auto mb-2 opacity-40 text-cyan-400 animate-pulse" size={24} />
        Awaiting risk forecast telemetry...
      </div>
    );
  }

  const isEscalating = forecast.trend === 'escalating';
  const points = forecast.forecast;
  const latestRisk = points[points.length - 1]?.risk || 0;

  return (
    <div className="space-y-4">
      {/* Header Metric Cards */}
      <div className="grid grid-cols-3 gap-3">
        <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase font-semibold">Baseline Risk</span>
          <div className="text-base font-black text-slate-200 mt-0.5">
            {forecast.baseline || 0}%
          </div>
        </div>

        <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase font-semibold">Projected Peak</span>
          <div className={`text-base font-black mt-0.5 ${latestRisk >= 75 ? 'text-red-400' : 'text-amber-400'}`}>
            {latestRisk}%
          </div>
        </div>

        <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800">
          <span className="text-[10px] text-slate-400 uppercase font-semibold">Trend</span>
          <div className="flex items-center gap-1 mt-0.5">
            {isEscalating ? (
              <span className="flex items-center gap-1 text-xs font-bold text-red-400">
                <TrendingUp size={14} /> Escalating
              </span>
            ) : (
              <span className="flex items-center gap-1 text-xs font-bold text-emerald-400">
                <TrendingDown size={14} /> Stable
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Chart Canvas */}
      <div className="p-3 bg-slate-900/40 rounded-xl border border-slate-800 h-[210px]">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={points} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <XAxis dataKey="label" stroke="#64748b" fontSize={10} tickLine={false} />
            <YAxis domain={[0, 100]} stroke="#64748b" fontSize={10} tickLine={false} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#0f172a',
                borderColor: '#334155',
                borderRadius: '8px',
                fontSize: '11px',
                color: '#f8fafc',
              }}
              formatter={(val) => [`${val}% Risk`, 'Projected']}
            />
            <Line
              type="monotone"
              dataKey="risk"
              stroke="#f43f5e"
              strokeWidth={2.5}
              dot={{ fill: '#f43f5e', r: 4 }}
              activeDot={{ r: 6, fill: '#fb7185' }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Evidence Drivers */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] text-slate-400 font-semibold uppercase">Drivers:</span>
        {(forecast.drivers || []).map((driver) => (
          <span
            key={driver}
            className="px-2 py-0.5 rounded-full bg-slate-800/80 border border-slate-700/60 text-[10px] text-slate-300 flex items-center gap-1"
          >
            <AlertTriangle size={10} className="text-amber-400" />
            {driver}
          </span>
        ))}
      </div>
    </div>
  );
}
