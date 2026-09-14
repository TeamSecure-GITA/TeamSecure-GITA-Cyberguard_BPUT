import React from 'react';
import { AlertTriangle, Link, ShieldCheck, UserX, Video } from 'lucide-react';

const threatTypes = [
	{ key: 'deepfake', label: 'Deepfake AI', icon: Video, color: 'text-fuchsia-300', track: 'bg-fuchsia-400' },
	{ key: 'ato', label: 'Behavioural ATO', icon: AlertTriangle, color: 'text-orange-300', track: 'bg-orange-400' },
	{ key: 'url', label: 'URL Intelligence', icon: Link, color: 'text-amber-300', track: 'bg-amber-400' },
	{ key: 'impersonation', label: 'Impersonation', icon: UserX, color: 'text-cyan-300', track: 'bg-cyan-400' },
];

export default function ThreatCards({ metrics }) {
	const counts = metrics?.byCategory || {};
	const total = threatTypes.reduce((sum, threat) => sum + (counts[threat.key] || 0), 0);

	return (
		<section className="space-y-3">
			<div className="flex items-center justify-between">
				<div>
					<p className="eyebrow">Priority detection coverage</p>
					<h3 className="text-sm font-bold text-slate-100">Upgrade engines</h3>
				</div>
				<span className="text-[10px] text-slate-400">{total} tracked events</span>
			</div>
			<div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
				{threatTypes.map((threat) => {
					const Icon = threat.icon;
					const count = counts[threat.key] || 0;
					const share = total ? Math.round((count / total) * 100) : 0;
					return (
						<div key={threat.key} className="bg-cardBg border border-slate-700/60 rounded-xl p-4">
							<div className="flex items-center justify-between">
								<span className={`flex items-center gap-2 text-xs font-semibold ${threat.color}`}><Icon size={16} />{threat.label}</span>
								{count > 0 ? <span className="text-[10px] text-emerald-300">active</span> : <ShieldCheck className="text-slate-600" size={15} />}
							</div>
							<div className="mt-4 flex items-end justify-between">
								<strong className="text-2xl text-white">{count}</strong>
								<span className="text-[10px] text-slate-500">{share}% of priority events</span>
							</div>
							<div className="mt-3 h-1.5 rounded-full bg-slate-800 overflow-hidden"><div className={`h-full ${threat.track} transition-all`} style={{ width: `${Math.max(share, count ? 8 : 0)}%` }} /></div>
						</div>
					);
				})}
			</div>
		</section>
	);
}
