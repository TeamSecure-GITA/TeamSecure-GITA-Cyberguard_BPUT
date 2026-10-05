import React, { useState } from 'react';
import { 
  Play, 
  ShieldAlert, 
  CheckCircle2, 
  ArrowRight, 
  X, 
  Link2, 
  Mic, 
  Globe, 
  Cpu, 
  Sparkles,
  Layers,
  Terminal
} from 'lucide-react';

const DEMO_SCENARIOS = [
  {
    id: 'phishing',
    title: 'Phishing Campaign Interception',
    type: 'URL / DOMAIN',
    icon: Link2,
    target: 'https://bput-exam-portal.verify-auth.xyz/login?student_id=9042',
    description: 'Deceptive student examination portal targeting BPUT engineering credentials with typosquatted domain and reverse-proxy MFA harvest.',
    riskScore: 94,
    verdict: 'MALICIOUS_PHISHING',
    indicators: [
      'Punycode / Typosquatting impersonating official university domain',
      'Obfuscated JavaScript credential exfiltration payload detected',
      'TLS certificate issued 14 minutes ago by Let\'s Encrypt with no CAA record',
      'Known bulletproof hosting ASN registered in high-risk autonomous system'
    ],
    action: 'Domain blocked at Cloudflare Edge WAF; all 18 impacted student sessions revoked and prompted for security reset.'
  },
  {
    id: 'deepfake',
    title: 'Synthetic Voice Authorization Clone',
    type: 'DEEPFAKE / AUDIO',
    icon: Mic,
    target: 'Audio Call: VC_Urgent_Procurement_Auth_0923.wav',
    description: 'High-frequency synthetic voice clone impersonating the Vice-Chancellor instructing expedited fund disbursement to unverified vendor account.',
    riskScore: 98,
    verdict: 'AI_SYNTHETIC_MEDIA',
    indicators: [
      'Spectral analysis reveals missing human glottal pulse harmonics between 3.2kHz - 4.5kHz',
      'Diffusion model residual phase artifacts identified in acoustic spectrogram',
      'Liveness verification challenge failed: non-natural vocal tract resonant jitter',
      'Caller IP traced to commercial VPN exit gateway'
    ],
    action: 'Disbursement authorization automatically quarantined; forensic incident report dispatched to Chief Financial Officer.'
  },
  {
    id: 'tor',
    title: 'Credential Stuffing via Tor Exit Nodes',
    type: 'TOR / NETWORK',
    icon: Globe,
    target: 'Network Flow: 185.220.101.45:9001 -> Campus LDAP Endpoint',
    description: 'Distributed brute-force credential stuffing spike attempting 4,200 requests/sec across faculty email authentication endpoints.',
    riskScore: 89,
    verdict: 'DISTRIBUTED_BRUTEFORCE',
    indicators: [
      'Traffic source matches verified Tor exit node list updated 3 minutes ago',
      'Rate-of-arrival exceeds baseline standard deviation by +840%',
      'Dictionary attack vector using leaked credentials from third-party breach',
      'Zero user agent header diversity with randomized ephemeral TCP source ports'
    ],
    action: 'Dynamic IP rate-limit clamped; CAPTCHA enforcement activated on all campus single-sign-on portals.'
  }
];

export default function WatchDemoModal({ isOpen, onClose, onLaunchWorkspace }) {
  const [selectedScenario, setSelectedScenario] = useState(DEMO_SCENARIOS[0]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analyzed, setAnalyzed] = useState(false);
  const [step, setStep] = useState(0);

  if (!isOpen) return null;

  const handleRunAnalysis = () => {
    setIsAnalyzing(true);
    setAnalyzed(false);
    setStep(1);

    setTimeout(() => setStep(2), 500);
    setTimeout(() => setStep(3), 1100);
    setTimeout(() => {
      setIsAnalyzing(false);
      setAnalyzed(true);
      setStep(4);
    }, 1800);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-md overflow-y-auto">
      <div className="relative w-full max-w-3xl rounded-2xl bg-[#061424] border border-cyan-500/30 shadow-[0_0_60px_rgba(6,182,212,0.3)] overflow-hidden my-auto animate-in fade-in zoom-in-95 duration-200">
        
        {/* Modal Top Header */}
        <div className="px-5 py-4 border-b border-slate-800 bg-[#040e1b] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              <Play size={18} className="text-cyan-400 fill-cyan-400/30" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base sm:text-lg font-bold text-white tracking-tight">
                  CyberGuard AI Interactive Threat Simulator
                </h3>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-emerald-950/60 text-emerald-400 border border-emerald-500/30">
                  LIVE DEMO
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Experience real-time AI signal detection, multi-modal explainability, and automated defense response.
              </p>
            </div>
          </div>
          
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 sm:p-6 space-y-5 max-h-[78vh] overflow-y-auto">
          {/* 1. Scenario Selector Tabs */}
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-2 uppercase tracking-wider">
              Select Threat Vector to Simulate:
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              {DEMO_SCENARIOS.map((scenario) => {
                const IconComponent = scenario.icon;
                const isSelected = selectedScenario.id === scenario.id;
                return (
                  <button
                    key={scenario.id}
                    onClick={() => {
                      setSelectedScenario(scenario);
                      setAnalyzed(false);
                      setStep(0);
                    }}
                    className={`flex items-start gap-2.5 p-3 rounded-xl border text-left transition-all ${
                      isSelected
                        ? 'bg-cyan-950/40 border-cyan-400 text-white shadow-[0_0_15px_rgba(6,182,212,0.25)]'
                        : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                    }`}
                  >
                    <IconComponent size={16} className={`shrink-0 mt-0.5 ${isSelected ? 'text-cyan-400' : 'text-slate-500'}`} />
                    <div>
                      <div className="text-xs font-bold leading-tight">{scenario.title}</div>
                      <div className="text-[10px] font-mono text-slate-400 mt-1">{scenario.type}</div>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* 2. Payload Inspection Box */}
          <div className="p-4 rounded-xl bg-[#030b14] border border-slate-800 space-y-3 font-mono">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="flex items-center gap-1.5 text-cyan-300">
                <Terminal size={14} />
                <span>INCOMING TELEMETRY PAYLOAD</span>
              </span>
              <span className="text-[10px] text-slate-500">FORMAT: JSON / RAW SENSOR</span>
            </div>
            <div className="p-2.5 rounded-lg bg-[#071320] border border-cyan-500/20 text-xs text-slate-200 break-all select-all font-mono">
              {selectedScenario.target}
            </div>
            <p className="text-xs text-slate-400 font-sans leading-relaxed">
              {selectedScenario.description}
            </p>
          </div>

          {/* 3. Action Trigger Button */}
          <div>
            <button
              onClick={handleRunAnalysis}
              disabled={isAnalyzing}
              className="w-full py-3.5 rounded-xl font-bold text-slate-950 text-sm flex items-center justify-center gap-2 transition-all shadow-[0_0_30px_rgba(16,185,129,0.3)] hover:shadow-[0_0_40px_rgba(6,182,212,0.5)] cursor-pointer disabled:opacity-60"
              style={{
                background: 'linear-gradient(135deg, #34d399 0%, #10b981 40%, #06b6d4 100%)',
              }}
            >
              {isAnalyzing ? (
                <>
                  <Cpu size={18} className="animate-spin text-slate-950" />
                  <span>
                    {step === 1 && 'Extracting Spectral & Semantic Artifacts...'}
                    {step === 2 && 'Querying Neural Threat Classifier...'}
                    {step === 3 && 'Synthesizing XAI Explanation & Containment...'}
                  </span>
                </>
              ) : (
                <>
                  <Sparkles size={18} className="text-slate-950" />
                  <span>Execute Neural AI Inspection</span>
                </>
              )}
            </button>
          </div>

          {/* 4. Analysis Results (Revealed after analysis) */}
          {analyzed && (
            <div className="space-y-4 pt-2 border-t border-slate-800 animate-in fade-in slide-in-from-top-2 duration-300">
              {/* Risk Gauge Bar */}
              <div className="p-4 rounded-xl bg-[#091b2e] border border-rose-500/40 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-[0_0_25px_rgba(244,63,94,0.15)]">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-rose-500/20 text-rose-400 border border-rose-500/40">
                    <ShieldAlert size={24} />
                  </div>
                  <div>
                    <span className="text-[10px] font-mono text-rose-400 font-bold tracking-wider">
                      DETECTION POSTURE: CRITICAL THREAT
                    </span>
                    <h4 className="text-base font-bold text-white">
                      Verdict: {selectedScenario.verdict}
                    </h4>
                  </div>
                </div>

                <div className="flex items-baseline gap-2 font-mono">
                  <span className="text-3xl font-extrabold text-rose-400">{selectedScenario.riskScore}</span>
                  <span className="text-xs text-slate-400">/ 100 RISK POSTURE</span>
                </div>
              </div>

              {/* Explainable AI Findings */}
              <div className="p-4 rounded-xl bg-[#040e1b] border border-slate-800 space-y-2.5">
                <span className="text-xs font-mono text-cyan-300 font-bold flex items-center gap-1.5">
                  <Layers size={14} />
                  <span>XAI (EXPLAINABLE AI) FORENSIC EVIDENCE:</span>
                </span>
                <ul className="space-y-1.5">
                  {selectedScenario.indicators.map((indicator, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-xs text-slate-300 leading-snug">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                      <span>{indicator}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Containment Next Steps */}
              <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/30 space-y-1.5">
                <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono font-bold">
                  <CheckCircle2 size={15} />
                  <span>AUTONOMOUS MITIGATION EXECUTED</span>
                </div>
                <p className="text-xs text-emerald-200 leading-relaxed">
                  {selectedScenario.action}
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-5 py-4 border-t border-slate-800 bg-[#040e1b] flex flex-col sm:flex-row items-center justify-between gap-3">
          <span className="text-xs text-slate-400 font-mono">
            Ready to explore full BPUT operational defense?
          </span>
          <button
            onClick={() => {
              onClose();
              onLaunchWorkspace();
            }}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl font-bold text-xs sm:text-sm bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors shadow-md cursor-pointer"
          >
            <span>Open Full SOC Workspace</span>
            <ArrowRight size={15} />
          </button>
        </div>

      </div>
    </div>
  );
}
