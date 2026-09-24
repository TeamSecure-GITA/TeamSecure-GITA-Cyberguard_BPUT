import React, { useEffect, useState } from 'react';
import ReactFlow, { Background, Controls, MarkerType } from 'reactflow';
import axios from 'axios';
import { GitBranch, RefreshCw } from 'lucide-react';
import 'reactflow/dist/style.css';

const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

const initialNodes = [
  { id: '1', position: { x: 50, y: 120 }, data: { label: 'Attacker (Threat Origin)' }, style: { background: '#ef4444', color: '#fff', borderRadius: '8px', border: '1px solid #b91c1c', fontWeight: 'bold', fontSize: '11px' } },
  { id: '2', position: { x: 260, y: 120 }, data: { label: 'Inbound Delivery Vector' }, style: { background: '#f59e0b', color: '#fff', borderRadius: '8px', border: '1px solid #d97706', fontWeight: 'bold', fontSize: '11px' } },
  { id: '3', position: { x: 480, y: 60 }, data: { label: 'Credential Harvesting Portal' }, style: { background: '#dc2626', color: '#fff', borderRadius: '8px', border: '1px solid #991b1b', fontWeight: 'bold', fontSize: '11px' } },
  { id: '4', position: { x: 480, y: 180 }, data: { label: 'Target Account / Identity' }, style: { background: '#0284c7', color: '#fff', borderRadius: '8px', border: '1px solid #0369a1', fontWeight: 'bold', fontSize: '11px' } },
  { id: '5', position: { x: 700, y: 120 }, data: { label: 'Internal SOC Asset Impact' }, style: { background: '#8b5cf6', color: '#fff', borderRadius: '8px', border: '1px solid #7c3aed', fontWeight: 'bold', fontSize: '11px' } },
];

const initialEdges = [
  { id: 'e1-2', source: '1', target: '2', animated: true, label: 'Sends Payload', style: { stroke: '#ef4444' } },
  { id: 'e2-3', source: '2', target: '3', animated: true, label: 'Redirects URL', style: { stroke: '#f59e0b' } },
  { id: 'e2-4', source: '2', target: '4', label: 'Compromises Session', style: { stroke: '#0284c7' } },
  { id: 'e3-5', source: '3', target: '5', animated: true, label: 'Lateral Movement', style: { stroke: '#dc2626' } },
  { id: 'e4-5', source: '4', target: '5', animated: true, label: 'Unauthorized Access', style: { stroke: '#8b5cf6' } },
];

export default function AttackGraph({ accessToken }) {
  const [mode, setMode] = useState('inferred'); // 'inferred' or 'topology'
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [graph, setGraph] = useState({ nodes: initialNodes, edges: initialEdges });
  const [chainEvents, setChainEvents] = useState([]);
  const [loading, setLoading] = useState(false);

  const config = { headers: { Authorization: `Bearer ${accessToken}` } };

  // Fetch recent incidents for selection
  useEffect(() => {
    axios.get(`${apiBaseUrl}/api/v1/incidents`, config)
      .then((res) => {
        const list = res.data.incidents || [];
        setIncidents(list);
        if (list.length > 0 && !selectedIncidentId) {
          setSelectedIncidentId(list[0].database_id);
        }
      })
      .catch(() => {});
  }, [accessToken]);

  // Load either inferred attack chain or aggregate topology
  useEffect(() => {
    if (mode === 'topology') {
      setLoading(true);
      axios.get(`${apiBaseUrl}/api/v1/dashboard/graph`, config)
        .then((response) => {
          if (response.data.nodes?.length) {
            setGraph(response.data);
          }
        })
        .catch(() => {})
        .finally(() => setLoading(false));
    } else if (selectedIncidentId) {
      setLoading(true);
      axios.get(`${apiBaseUrl}/api/v1/incidents/${selectedIncidentId}/attack-chain`, config)
        .then((res) => {
          const events = res.data.events || [];
          setChainEvents(events);

          if (events.length > 0) {
            const stepColors = ['#ef4444', '#f59e0b', '#dc2626', '#0284c7', '#8b5cf6'];
            const newNodes = events.map((ev, index) => ({
              id: `node-${index}`,
              position: { x: 40 + index * 180, y: 100 + (index % 2 === 0 ? 0 : 50) },
              data: {
                label: (
                  <div className="text-left">
                    <div className="text-[9px] uppercase tracking-wider text-slate-300 font-bold opacity-80">{ev.id}</div>
                    <div className="text-[11px] font-bold text-white">{ev.label}</div>
                    <div className="text-[9px] text-slate-200 truncate max-w-[130px] opacity-75">{ev.detail}</div>
                  </div>
                ),
              },
              style: {
                background: stepColors[index % stepColors.length],
                color: '#fff',
                borderRadius: '10px',
                padding: '8px 10px',
                border: '1px solid rgba(255,255,255,0.2)',
                boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
                width: 160,
              },
            }));

            const newEdges = [];
            for (let i = 0; i < newNodes.length - 1; i++) {
              newEdges.push({
                id: `edge-${i}-${i + 1}`,
                source: newNodes[i].id,
                target: newNodes[i + 1].id,
                animated: true,
                style: { stroke: '#38bdf8', strokeWidth: 2 },
                markerEnd: { type: MarkerType.ArrowClosed, color: '#38bdf8' },
              });
            }

            setGraph({ nodes: newNodes, edges: newEdges });
          }
        })
        .catch(() => {})
        .finally(() => setLoading(false));
    }
  }, [mode, selectedIncidentId, accessToken]);

  return (
    <div className="space-y-4">
      {/* Header Controls */}
      <div className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-bold text-cyan-400 uppercase tracking-wider">
            <GitBranch size={16} /> AI Attack Chain Reconstruction & Graph
          </div>
          <h3 className="text-base font-bold text-white mt-0.5">
            Inferred Threat Attack Progression Flow
          </h3>
          <p className="text-xs text-slate-400">
            Interactive node analysis tracing the kill-chain from Initial Access to Target Impact.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {mode === 'inferred' && incidents.length > 0 && (
            <select
              value={selectedIncidentId || ''}
              onChange={(e) => setSelectedIncidentId(Number(e.target.value))}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {incidents.map((inc) => (
                <option key={inc.database_id} value={inc.database_id}>
                  {inc.id} · {inc.category} ({inc.riskScore}%)
                </option>
              ))}
            </select>
          )}

          <div className="flex items-center rounded-lg bg-slate-900 p-1 border border-slate-800">
            <button
              type="button"
              onClick={() => setMode('inferred')}
              className={`px-3 py-1 text-xs font-semibold rounded-md transition ${
                mode === 'inferred'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Inferred Chain
            </button>
            <button
              type="button"
              onClick={() => setMode('topology')}
              className={`px-3 py-1 text-xs font-semibold rounded-md transition ${
                mode === 'topology'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              SOC Topology
            </button>
          </div>
        </div>
      </div>

      {/* Graph Visualizer Canvas */}
      <div className="bg-cardBg border border-slate-700/60 rounded-xl p-4 shadow-lg h-[460px] flex flex-col">
        <div className="flex-1 border border-slate-800 rounded-lg bg-slate-950/80 overflow-hidden relative">
          {loading && (
            <div className="absolute inset-0 bg-slate-950/60 z-10 flex items-center justify-center text-xs text-cyan-400 font-semibold gap-2">
              <RefreshCw size={16} className="animate-spin" /> Inferring graph connections...
            </div>
          )}
          <ReactFlow nodes={graph.nodes} edges={graph.edges} fitView>
            <Background color="#1e293b" gap={18} size={1} />
            <Controls />
          </ReactFlow>
        </div>

        {mode === 'inferred' && chainEvents.length > 0 && (
          <div className="mt-3 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 px-1">
            <span>{chainEvents.length} Attack Chain stages reconstructed by CyberGuard Reasoning Engine</span>
            <span className="text-cyan-400 font-mono text-[11px]">MITRE ATT&CK Framework Aligned</span>
          </div>
        )}
      </div>
    </div>
  );
}