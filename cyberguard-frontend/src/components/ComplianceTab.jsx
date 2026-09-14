import React, { useEffect, useState } from 'react';
import { CheckCircle2, AlertTriangle, FileText, Network } from 'lucide-react';
import axios from 'axios';

export default function ComplianceTab({ accessToken }) {
  const [complianceData, setComplianceData] = useState([
    {
      framework: 'CERT-In 6-Hour Reporting Mandate',
      status: 'Compliant',
      score: '100%',
      description: 'Automated threat categorization and incident log generation configured for immediate reporting.',
      icon: CheckCircle2,
      color: 'text-emerald-400',
    },
    {
      framework: 'DPDP Act (Data Protection & Privacy)',
      status: 'Compliant',
      score: '98%',
      description: 'Role-Based Access Control (RBAC) enforced with dynamic PII masking on threat logs.',
      icon: CheckCircle2,
      color: 'text-emerald-400',
    },
    {
      framework: 'ISO 27001 ISMS Controls',
      status: 'Needs Review',
      score: '84%',
      description: 'Access control policies matched. Real-time log retention strategy needs validation.',
      icon: AlertTriangle,
      color: 'text-amber-400',
    },
  ]);
  const [mitreMappings, setMitreMappings] = useState([]);

  useEffect(() => {
    const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';
    const config = { headers: { Authorization: `Bearer ${accessToken}` } };
    Promise.all([
      axios.get(`${apiBaseUrl}/api/v1/compliance/controls`, config),
      axios.get(`${apiBaseUrl}/api/v1/compliance/mitre`, config),
    ]).then(([controls, mitre]) => {
      setComplianceData(controls.data.controls.map((item) => ({ ...item, description: item.evidence, icon: item.status === 'Compliant' ? CheckCircle2 : AlertTriangle, color: item.status === 'Compliant' ? 'text-emerald-400' : 'text-amber-400' })));
      setMitreMappings(mitre.data.mappings);
    }).catch(() => {});
  }, [accessToken]);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold text-slate-100">National Cybersecurity & Institutional Compliance</h2>
          <p className="text-xs text-slate-400">Automated mapping against Indian Cybersecurity Standards & Guidelines</p>
        </div>
        <button className="flex items-center space-x-2 bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 px-4 py-2 rounded-xl text-xs font-semibold hover:bg-cyan-500/20 transition">
          <FileText size={16} />
          <span>Generate Audit Certificate</span>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {complianceData.map((item, idx) => {
          const Icon = item.icon;
          return (
            <div key={idx} className="bg-cardBg border border-slate-700/60 rounded-xl p-5 space-y-3">
              <div className="flex justify-between items-start">
                <Icon className={item.color} size={24} />
                <span className="text-lg font-bold text-slate-200">{item.score}</span>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-slate-200">{item.framework}</h3>
                <span className={`inline-block text-[10px] font-bold px-2 py-0.5 rounded-md mt-1 ${
                  item.status === 'Compliant' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                }`}>
                  {item.status}
                </span>
              </div>
              <p className="text-xs text-slate-400">{item.description}</p>
            </div>
          );
        })}
      </div>
      <div className="bg-cardBg border border-slate-700/60 rounded-xl p-5">
        <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2"><Network size={17} className="text-cyan-400" /> MITRE ATT&CK Coverage</h3>
        <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
          {mitreMappings.map((mapping) => <div key={mapping.technique} className="p-3 rounded-lg bg-slate-900/60 border border-slate-800"><p className="text-xs font-bold text-cyan-300">{mapping.technique} / {mapping.name}</p><p className="mt-1 text-[10px] text-slate-400">Mapped sources: {mapping.categories.join(', ')}</p></div>)}
        </div>
      </div>
    </div>
  );
}