import React from 'react';
import { CheckCircle2, Cpu, Database, ExternalLink, Radio } from 'lucide-react';

export default function SystemView({ health, modelStatus }) {
	const media = modelStatus?.deep_learning_adapter || {};
	const detectorState = (kind) => media.loaded?.includes(kind) ? 'Loaded' : media.weights_cached?.[kind] ? 'Cached · lazy load' : media.enabled ? 'Weights not cached' : 'Disabled';
	const systems = [
		{ label: 'FastAPI detection API', value: health?.status === 'healthy' ? 'Operational' : 'Unavailable', icon: Radio, ok: health?.status === 'healthy' },
		{ label: 'Text classifier', value: modelStatus?.text_classifier?.loaded ? modelStatus.text_classifier.algorithm : 'Rules only', icon: Cpu, ok: modelStatus?.text_classifier?.loaded },
		{ label: 'Media triage', value: modelStatus?.media_inspection?.available ? 'Heuristic ready' : 'Unavailable', icon: ExternalLink, ok: modelStatus?.media_inspection?.available },
		{ label: 'Image detector', value: detectorState('image'), icon: ExternalLink, ok: media.loaded?.includes('image') },
		{ label: 'Audio detector', value: detectorState('audio'), icon: ExternalLink, ok: media.loaded?.includes('audio') },
		{ label: 'Incident database', value: health?.database ? `${health.database} · ${health.events_stored ?? 0} events` : 'Unavailable', icon: Database, ok: Boolean(health?.database) },
		{ label: 'Ephemeral state', value: health?.ephemeral_state || 'Unavailable', icon: Database, ok: health?.ephemeral_state === 'redis' },
	];

	return (
		<section className="bg-cardBg border border-slate-700/60 rounded-xl p-5">
			<div className="flex items-center justify-between"><div><p className="eyebrow">Runtime status</p><h3 className="text-sm font-bold text-slate-100">System view</h3></div><span className={`text-[10px] font-bold uppercase ${health?.status === 'healthy' ? 'text-emerald-300' : 'text-amber-300'}`}>{health?.status || 'checking'}</span></div>
			<div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-2">
				{systems.map((system) => { const Icon = system.icon; return <div key={system.label} className="flex items-center gap-3 p-3 rounded-lg bg-slate-950/40 border border-slate-800"><Icon size={16} className={system.ok ? 'text-emerald-400' : 'text-amber-400'} /><div className="min-w-0 flex-1"><p className="text-[10px] text-slate-400 truncate">{system.label}</p><p className="text-xs font-semibold text-slate-200">{system.value}</p></div>{system.ok && <CheckCircle2 size={14} className="text-emerald-400" />}</div>; })}
			</div>
		</section>
	);
}
