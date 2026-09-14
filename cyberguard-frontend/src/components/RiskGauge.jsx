import React from 'react';

export default function RiskGauge({ metrics }) {
	const levels = metrics?.byLevel || {};
	const total = Object.values(levels).reduce((sum, value) => sum + value, 0);
	const weightedScore = total ? Math.round(Object.entries(levels).reduce((sum, [level, count]) => sum + ({ Safe: 0, Low: 20, Medium: 45, High: 72, Critical: 95 }[level] || 0) * count, 0) / total) : 0;
	const label = weightedScore >= 80 ? 'Critical' : weightedScore >= 60 ? 'High' : weightedScore >= 35 ? 'Guarded' : 'Stable';
	const color = weightedScore >= 80 ? '#f87171' : weightedScore >= 60 ? '#fb923c' : weightedScore >= 35 ? '#fbbf24' : '#34d399';

	return (
		<section className="bg-cardBg border border-slate-700/60 rounded-xl p-5">
			<div className="flex items-center justify-between"><div><p className="eyebrow">Risk engine</p><h3 className="text-sm font-bold text-slate-100">Overall risk posture</h3></div><span className="text-[10px] text-slate-500">{total} scored events</span></div>
			<div className="mt-5 flex items-center gap-5">
				<div className="relative grid place-items-center w-32 h-32 rounded-full" style={{ background: `conic-gradient(${color} ${weightedScore * 3.6}deg, #1e293b 0deg)` }}>
					<div className="grid place-items-center w-24 h-24 rounded-full bg-slate-950"><strong className="text-2xl text-white">{weightedScore}</strong><span className="text-[9px] uppercase text-slate-500">risk index</span></div>
				</div>
				<div className="space-y-2 text-xs flex-1">
					<div className="flex justify-between"><span className="text-slate-400">Posture</span><strong style={{ color }}>{label}</strong></div>
					{['Critical', 'High', 'Medium', 'Low', 'Safe'].map((level) => <div key={level} className="flex justify-between text-[10px]"><span className="text-slate-500">{level}</span><span className="text-slate-300">{levels[level] || 0}</span></div>)}
				</div>
			</div>
		</section>
	);
}
