import React, { useEffect, useState } from 'react';
import { X, AlertOctagon, Cpu, ShieldAlert, Download } from 'lucide-react';
import { jsPDF } from 'jspdf';
import axios from 'axios';

export default function XaiModal({ incident, onClose, userRole, accessToken }) {
  const [detail, setDetail] = useState(null);
  const [genome, setGenome] = useState(null);
  const [correlations, setCorrelations] = useState(null);
  const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
  useEffect(() => {
    if (!incident?.database_id) return;
    const config = { headers: { Authorization: `Bearer ${accessToken}` } };
    Promise.all([
      axios.get(`${apiBaseUrl}/api/v1/incidents/${incident.database_id}`, config),
      axios.get(`${apiBaseUrl}/api/v1/incidents/${incident.database_id}/genome`, config),
      axios.get(`${apiBaseUrl}/api/v1/incidents/${incident.database_id}/correlations`, config),
    ]).then(([detailResponse, genomeResponse, correlationResponse]) => {
      setDetail(detailResponse.data.incident);
      setGenome(genomeResponse.data.genome);
      setCorrelations(correlationResponse.data);
    }).catch(() => { setDetail(null); setGenome(null); setCorrelations(null); });
  }, [incident, accessToken, apiBaseUrl]);

  if (!incident) return null;

  const handleDownloadPDF = () => {
    const doc = new jsPDF();
    
    // Header
    doc.setFillColor(15, 23, 42); // Dark slate background header
    doc.rect(0, 0, 210, 30, 'F');
    doc.setTextColor(56, 189, 248);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text('CYBERGUARD - Official Threat Intelligence Report', 10, 18);
    
    // Incident Metadata
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text(`Incident ID: ${incident.id}`, 10, 40);
    doc.text(`Timestamp: ${incident.timestamp}`, 10, 46);
    doc.text(`Target Entity: ${incident.target}`, 10, 52);
    doc.text(`Threat Category: ${incident.category}`, 10, 58);
    doc.text(`Severity Level: ${incident.riskLevel} (${incident.riskScore}%)`, 10, 64);

    // XAI Assessment Summary
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Explainable AI (XAI) Finding:', 10, 78);
    
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    const splitExplanation = doc.splitTextToSize(
      incident.explanation || "High Risk: Language pattern urgency and look-alike domain signatures identified by FastAPI engine.",
      190
    );
    doc.text(splitExplanation, 10, 86);

    // Save File
    doc.save(`CYBERGUARD_Report_${incident.id}.pdf`);
  };

  const executeAction = async (actionId, label) => {
    try {
      await axios.post('http://127.0.0.1:8000/api/v1/response/execute', {
        incident_id: incident.id,
        action_id: actionId,
        target: incident.target,
      }, { headers: { Authorization: `Bearer ${accessToken}` } });
      alert(`Action executed: ${label} for ${incident.id}`);
      onClose();
    } catch (error) {
      alert(error.response?.data?.detail || 'Response action failed.');
    }
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-cardBg border border-slate-700 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-700 flex items-center justify-between bg-slate-900/50">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-cyan-500/10 rounded-lg text-cyan-400 border border-cyan-500/20">
              <Cpu size={20} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">Explainable AI Threat Assessment</h3>
              <p className="text-xs text-slate-400 font-mono">Incident Target: {incident.id}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded-lg bg-slate-800 transition">
            <X size={20} />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-5">
          <div className="flex items-center justify-between p-4 bg-slate-900/80 rounded-xl border border-slate-800">
            <div>
              <span className="text-xs text-slate-400 uppercase font-semibold">Calculated Threat Level</span>
              <div className="text-2xl font-black text-red-400 mt-0.5">{incident.riskLevel} ({incident.riskScore}%)</div>
            </div>
            <button
              onClick={handleDownloadPDF}
              className="px-3 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center gap-2 transition"
            >
              <Download size={14} /> Download PDF Report
            </button>
          </div>

          <div>
            <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Explainable AI (XAI) Reason</h4>
            <div className="p-4 bg-slate-900 border border-cyan-500/30 rounded-xl text-sm text-slate-200">
              "{incident.explanation || 'Suspicious urgency indicators and anomalous domain signatures identified by AI models.'}"
            </div>
            {detail?.assessment && <div className="mt-2 flex flex-wrap gap-2 text-[10px]">
              <span className="px-2 py-1 rounded-md bg-cyan-500/10 border border-cyan-500/20 text-cyan-300">Engine: {detail.assessment.detection_method || 'multi-engine'}</span>
              {(detail.assessment.mitre_techniques || []).map((technique) => <span key={technique} className="px-2 py-1 rounded-md bg-amber-500/10 border border-amber-500/20 text-amber-300">MITRE {technique}</span>)}
            </div>}
          </div>

          <div className="xai-section-grid">
            <div className="xai-section"><div className="xai-section-title"><span>Threat DNA</span><strong>{genome?.similarity_score || 0}% match</strong></div><div className="flex items-center gap-3"><div className="genome-core">{genome?.fingerprint?.slice(0, 4) || 'DNA'}</div><div><strong className="text-cyan-300 font-mono text-sm">{genome?.fingerprint || 'Fingerprint pending'}</strong><p className="confidence-copy text-left">{genome?.vectors?.techniques?.join(', ') || 'No mapped techniques yet'}</p></div></div></div>
            <div className="xai-section"><div className="xai-section-title"><span>Related incidents</span><strong>{correlations?.related_incidents?.length || 0} linked</strong></div><div className="space-y-2">{(correlations?.related_incidents || []).slice(0, 3).map((related) => <div className="flex justify-between text-[10px] text-slate-300" key={related.incident_id}><span>{related.incident_id}</span><b className="text-emerald-300">{related.score}%</b></div>)}{!correlations?.related_incidents?.length && <p className="text-xs text-slate-500">No related incidents.</p>}</div></div>
          </div>

          <div className="xai-section-grid">
            <div className="xai-section"><div className="xai-section-title"><span>Risk factors</span><strong>{detail?.assessment?.signal_count || incident.indicators?.length || 0} signals</strong></div>{(detail?.assessment?.indicators || incident.indicators || []).slice(0, 5).map((indicator, index) => <div className="factor-row" key={`${indicator.name}-${index}`}><div><span>{indicator.name}</span><b>{indicator.score}</b></div><div className="factor-track"><i style={{ width: indicator.score }} /></div></div>)}</div>
            <div className="xai-section"><div className="xai-section-title"><span>AI confidence</span><strong>{incident.riskScore}%</strong></div><div className="confidence-ring" style={{ '--confidence': incident.riskScore }}><div><b>{incident.riskScore}%</b><span>confidence</span></div></div><p className="confidence-copy">Confidence is based on model evidence, detector signals, and enriched indicators.</p></div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Evidence / IOCs</h4>
              <div className="space-y-1">{(detail?.assessment?.iocs || incident.iocs || []).map((ioc, index) => <div key={`${ioc.value}-${index}`} className="text-[11px] text-slate-300"><span className="text-cyan-400 uppercase">{ioc.type}</span> {ioc.value} <span className="text-slate-500">· {ioc.reputation || 'unknown'} ({ioc.risk_score ?? '--'})</span></div>)}{!(detail?.assessment?.iocs || incident.iocs || []).length && <p className="text-xs text-slate-500">No indicators extracted.</p>}</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Action History</h4>
              <div className="space-y-1">{(detail?.actions || []).map((action, index) => <div key={`${action.created_at}-${index}`} className="text-[11px] text-slate-300">{action.action_id} · {action.status}</div>)}{!(detail?.actions || []).length && <p className="text-xs text-slate-500">No actions recorded.</p>}</div>
            </div>
          </div>

          {/* Role Controlled Actions */}
          <div>
            <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
              Automated Incident Response {userRole === 'analyst' && '(Requires Lead Role to Trigger)'}
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <button
                disabled={userRole === 'analyst'}
                onClick={() => executeAction('block_domain', 'Domain Blocked')}
                className="bg-red-600 hover:bg-red-700 disabled:opacity-40 text-white text-xs font-semibold py-2.5 px-3 rounded-xl flex items-center justify-center gap-2 transition"
              >
                <ShieldAlert size={14} /> Block Suspicious Domain / IP
              </button>
              <button
                disabled={userRole === 'analyst'}
                onClick={() => executeAction('quarantine', 'Email Quarantined')}
                className="bg-amber-600 hover:bg-amber-700 disabled:opacity-40 text-white text-xs font-semibold py-2.5 px-3 rounded-xl flex items-center justify-center gap-2 transition"
              >
                <AlertOctagon size={14} /> Quarantine Email / Media
              </button>
              <button
                disabled={userRole === 'analyst'}
                onClick={() => executeAction('revoke_session', 'MFA Enforced')}
                className="bg-cyan-700 hover:bg-cyan-600 disabled:opacity-40 text-white text-xs font-semibold py-2.5 px-3 rounded-xl flex items-center justify-center gap-2 transition"
              >
                <ShieldAlert size={14} /> Revoke Session / Enforce MFA
              </button>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}