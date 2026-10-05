import React, { useEffect, useState } from 'react';
import ReactFlow, { Background, Controls, MarkerType } from 'reactflow';
import axios from 'axios';
import { GitBranch, RefreshCw } from 'lucide-react';
import { getApiBaseUrl } from '../apiConfig';
import 'reactflow/dist/style.css';

const apiBaseUrl = getApiBaseUrl();

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
  const [supplyChainInventory, setSupplyChainInventory] = useState(JSON.stringify([
    { id: 'vendor-1', name: 'Shared package vendor', criticality: 'high' },
    { id: 'service-1', name: 'Payments API', criticality: 'critical' },
    { id: 'service-2', name: 'Customer portal', criticality: 'high' },
  ], null, 2));
  const [supplyChainDependencies, setSupplyChainDependencies] = useState(JSON.stringify([
    { supplier: 'vendor-1', dependent: 'service-1' },
    { supplier: 'service-1', dependent: 'service-2' },
  ], null, 2));
  const [compromisedNodes, setCompromisedNodes] = useState('["vendor-1"]');
  const [supplyChainResult, setSupplyChainResult] = useState(null);
  const [supplyChainError, setSupplyChainError] = useState('');
  const [supplyChainBusy, setSupplyChainBusy] = useState(false);
  const [selectedIncidentOverride, setSelectedIncidentOverride] = useState(null);
  const selectedIncidentId = incidents.some((incident) => incident.database_id === selectedIncidentOverride)
    ? selectedIncidentOverride
    : incidents[0]?.database_id || null;
  const [graph, setGraph] = useState({ nodes: initialNodes, edges: initialEdges });
  const [chainEvents, setChainEvents] = useState([]);
  const [loadedGraphKey, setLoadedGraphKey] = useState(null);
  const requestKey = mode === 'topology' ? 'topology' : `incident:${selectedIncidentId ?? 'none'}`;
  const loading = Boolean(mode === 'topology' || (mode === 'inferred' && selectedIncidentId)) && loadedGraphKey !== requestKey;

  // Fetch recent incidents for selection
  useEffect(() => {
    const config = { headers: { Authorization: `Bearer ${accessToken}` } };
    axios.get(`${apiBaseUrl}/api/v1/incidents`, config)
      .then((res) => {
        const list = res.data.incidents || [];
        setIncidents(list);
      })
      .catch(() => {});
  }, [accessToken]);

  // Load either inferred attack chain or aggregate topology
  useEffect(() => {
    const config = { headers: { Authorization: `Bearer ${accessToken}` } };
    let active = true;
    if (mode === 'topology') {
      axios.get(`${apiBaseUrl}/api/v1/dashboard/graph`, config)
        .then((response) => {
          if (response.data.nodes?.length) {
            setGraph(response.data);
          }
        })
        .catch(() => {})
        .finally(() => { if (active) setLoadedGraphKey(requestKey); });
    } else if (mode === 'inferred' && selectedIncidentId) {
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
        .finally(() => { if (active) setLoadedGraphKey(requestKey); });
    }
    return () => { active = false; };
  }, [mode, selectedIncidentId, accessToken, requestKey]);

  const analyzeSupplyChain = async () => {
    setSupplyChainError('');
    setSupplyChainBusy(true);
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/roadmap/supply-chain`, {
        nodes: JSON.parse(supplyChainInventory),
        dependencies: JSON.parse(supplyChainDependencies),
        compromised_nodes: JSON.parse(compromisedNodes),
      }, { headers: { Authorization: 'Bearer ' + accessToken } });
      const result = response.data;
      setSupplyChainResult(result);
      const affectedById = new Map(result.affected_nodes.map((node) => [node.id, node]));
      const ids = [...new Set([
        ...result.compromised_nodes,
        ...result.affected_nodes.map((node) => node.id),
      ])];
      const nodes = ids.map((id, index) => {
        const knownNode = affectedById.get(id);
        return {
          id,
          position: { x: 60 + (index % 4) * 210, y: 60 + Math.floor(index / 4) * 120 },
          data: { label: knownNode ? knownNode.name : id + ' (compromised)' },
          style: {
            background: result.compromised_nodes.includes(id) ? '#dc2626' : '#0284c7',
            color: '#fff',
            borderRadius: '8px',
            border: '1px solid rgba(255,255,255,0.25)',
            fontWeight: 'bold',
            fontSize: '11px',
          },
        };
      });
      const edgeMap = new Map();
      result.affected_nodes.forEach((node) => {
        node.dependency_chain.slice(0, -1).forEach((supplier, index) => {
          const dependent = node.dependency_chain[index + 1];
          const id = `${supplier}-${dependent}`;
          edgeMap.set(id, {
            id,
            source: supplier,
            target: dependent,
            label: 'supplier dependency',
            markerEnd: { type: MarkerType.ArrowClosed, color: '#38bdf8' },
            style: { stroke: '#38bdf8' },
          });
        });
      });
      setGraph({ nodes, edges: [...edgeMap.values()] });
    } catch (error) {
      setSupplyChainResult(null);
      const detail = error.response?.data?.detail;
      const message = Array.isArray(detail)
        ? detail.map((item) => item.msg || JSON.stringify(item)).join('; ')
        : detail || error.message || 'Supply-chain analysis failed.';
      setSupplyChainError(message);
    } finally {
      setSupplyChainBusy(false);
    }
  };

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
              onChange={(e) => setSelectedIncidentOverride(Number(e.target.value))}
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
            <button
              type="button"
              onClick={() => setMode('supply-chain')}
              className={`px-3 py-1 text-xs font-semibold rounded-md transition ${
                mode === 'supply-chain'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Supply Chain
            </button>
          </div>
        </div>
      </div>

      {mode === 'supply-chain' && (
        <section className="bg-cardBg border border-slate-700/60 rounded-xl p-5 shadow-lg space-y-3">
          <div>
            <h3 className="text-sm font-bold text-white">Supplier compromise blast radius</h3>
            <p className="text-xs text-slate-400 mt-1">
              Enter your supplier-to-dependent inventory. This is a data-driven simulation using only the graph and compromise signals you provide.
            </p>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
            <label className="text-xs text-slate-300 space-y-1">
              Nodes (JSON array)
              <textarea value={supplyChainInventory} onChange={(event) => setSupplyChainInventory(event.target.value)} rows={7} className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 font-mono text-[11px] text-slate-200" />
            </label>
            <label className="text-xs text-slate-300 space-y-1">
              Dependencies (JSON array)
              <textarea value={supplyChainDependencies} onChange={(event) => setSupplyChainDependencies(event.target.value)} rows={7} className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 font-mono text-[11px] text-slate-200" />
            </label>
            <label className="text-xs text-slate-300 space-y-1">
              Compromised node IDs (JSON array)
              <textarea value={compromisedNodes} onChange={(event) => setCompromisedNodes(event.target.value)} rows={7} className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 font-mono text-[11px] text-slate-200" />
            </label>
          </div>
          <button type="button" disabled={supplyChainBusy} onClick={analyzeSupplyChain} className="px-4 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-200 text-xs font-semibold disabled:opacity-50">
            {supplyChainBusy ? 'Calculating…' : 'Calculate blast radius'}
          </button>
          {supplyChainError && <p role="alert" className="text-xs text-rose-300">{supplyChainError}</p>}
          {supplyChainResult && (
            <p className="text-xs text-slate-300" role="status">
              {supplyChainResult.affected_count} downstream node(s) affected — {supplyChainResult.mode}.
            </p>
          )}
        </section>
      )}

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