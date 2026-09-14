import React, { useEffect, useState } from 'react';
import ReactFlow, { Background, Controls } from 'reactflow';
import axios from 'axios';
import 'reactflow/dist/style.css';

const initialNodes = [
  { id: '1', position: { x: 50, y: 100 }, data: { label: 'Attacker (Spoofed IP)' }, style: { background: '#ef4444', color: '#fff', borderRadius: '8px' } },
  { id: '2', position: { x: 300, y: 100 }, data: { label: 'Phishing Email Gateway' }, style: { background: '#f59e0b', color: '#fff', borderRadius: '8px' } },
  { id: '3', position: { x: 550, y: 50 }, data: { label: 'Credential Theft Portal' }, style: { background: '#dc2626', color: '#fff', borderRadius: '8px' } },
  { id: '4', position: { x: 550, y: 150 }, data: { label: 'Target Student Account' }, style: { background: '#0284c7', color: '#fff', borderRadius: '8px' } },
];

const initialEdges = [
  { id: 'e1-2', source: '1', target: '2', animated: true, label: 'Sends Payload' },
  { id: 'e2-3', source: '2', target: '3', animated: true, label: 'Redirects URL' },
  { id: 'e2-4', source: '2', target: '4', label: 'Compromises Session' },
];

export default function AttackGraph({ accessToken }) {
  const [graph, setGraph] = useState({ nodes: initialNodes, edges: initialEdges });

  useEffect(() => {
    axios.get('http://127.0.0.1:8000/api/v1/dashboard/graph', {
      headers: { Authorization: `Bearer ${accessToken}` },
    }).then((response) => setGraph(response.data)).catch(() => {});
  }, [accessToken]);

  return (
    <div className="bg-cardBg border border-slate-700/60 rounded-xl p-6 shadow-lg h-[400px]">
      <h3 className="text-sm font-bold text-slate-200 mb-2">Live Threat Attack Propagation Graph</h3>
      <p className="text-xs text-slate-400 mb-4">Visual node analysis mapping threat vector origin to compromised assets.</p>
      <div className="h-[300px] border border-slate-800 rounded-lg bg-slate-900/50">
        <ReactFlow nodes={graph.nodes} edges={graph.edges} fitView>
          <Background color="#334155" gap={16} />
          <Controls />
        </ReactFlow>
      </div>
    </div>
  );
}