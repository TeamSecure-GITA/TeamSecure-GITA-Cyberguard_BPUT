import React, { useEffect, useState } from 'react';
import { Mail, Video, Link, FileText, UserX, AlertTriangle, Upload, Search, Loader2, PlayCircle, Globe } from 'lucide-react';
import axios from 'axios';

export default function ThreatInspector({ accessToken }) {
  const [activeSubTab, setActiveSubTab] = useState('email');
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [scanStage, setScanStage] = useState('idle');
  const [dragActive, setDragActive] = useState(false);
  const [liveAssessment, setLiveAssessment] = useState(null);
  const [liveLoading, setLiveLoading] = useState(false);
  const [adversarialResult, setAdversarialResult] = useState(null);
  const [adversarialLoading, setAdversarialLoading] = useState(false);
  const [assistantResult, setAssistantResult] = useState(null);
  const [assistantLoading, setAssistantLoading] = useState(false);
  const [plainMode, setPlainMode] = useState(false);
  const [complaintDraft, setComplaintDraft] = useState(null);

  const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

  useEffect(() => {
    if (activeSubTab !== 'email' || !inputText.trim()) {
      setLiveAssessment(null);
      setLiveLoading(false);
      return undefined;
    }

    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      setLiveLoading(true);
      try {
        const response = await axios.post(`${apiBaseUrl}/api/v1/analyze/preview`, {
          category: 'email',
          payload: inputText,
        }, { headers: { Authorization: `Bearer ${accessToken}` }, signal: controller.signal });
        setLiveAssessment(response.data?.assessment || null);
      } catch (previewError) {
        if (!axios.isCancel(previewError)) setLiveAssessment(null);
      } finally {
        if (!controller.signal.aborted) setLiveLoading(false);
      }
    }, 500);

    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [activeSubTab, inputText, accessToken, apiBaseUrl]);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!inputText.trim() && !(['image', 'audio', 'video', 'deepfake', 'email_file'].includes(activeSubTab) && selectedFile)) return;

    setLoading(true);
    setScanStage('scanning');
    setError(null);
    setAnalysisResult(null);

    try {
      const config = { headers: { Authorization: `Bearer ${accessToken}` } };
      let response;
      if (activeSubTab === 'website') {
        response = await axios.post(`${apiBaseUrl}/api/v1/analyze/website`, { url: inputText }, config);
      } else if (['image', 'audio', 'video', 'deepfake', 'email_file'].includes(activeSubTab) && selectedFile) {
        const formData = new FormData();
        formData.append('category', activeSubTab === 'email_file' ? 'email' : activeSubTab);
        formData.append('file', selectedFile);
        response = await axios.post(`${apiBaseUrl}/api/v1/analyze/file`, formData, config);
      } else {
        response = await axios.post(`${apiBaseUrl}/api/v1/analyze`, {
          category: activeSubTab,
          payload: inputText,
        }, config);
      }

      if (response.data?.assessment) {
        setAnalysisResult({ ...response.data.assessment, incident_id: response.data.incident_id });
        setAssistantResult(null);
        setComplaintDraft(null);
        setScanStage('ready');
      }
    } catch {
      setError('Failed to connect to CYBERGUARD AI Engine. Ensure FastAPI backend is running on port 8000.');
      setScanStage('idle');
    } finally {
      setLoading(false);
    }
  };

  const askAnalystAssistant = async () => {
    if (!analysisResult) return;
    setAssistantLoading(true);
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/assistant/analyze`, { assessment: analysisResult }, { headers: { Authorization: `Bearer ${accessToken}` } });
      setAssistantResult(response.data?.assistant || null);
    } finally {
      setAssistantLoading(false);
    }
  };

  const downloadComplaintDraft = async () => {
    if (!analysisResult?.incident_id) return;
    const response = await axios.get(`${apiBaseUrl}/api/v1/incidents/${analysisResult.incident_id}/complaint-draft`, { headers: { Authorization: `Bearer ${accessToken}` } });
    setComplaintDraft(response.data);
    const blob = new Blob([response.data.body], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `cyberguard-complaint-${response.data.incident_id}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const runAdversarialTest = async () => {
    if (!inputText.trim()) return;
    setAdversarialLoading(true);
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/adversarial/self-test`, { category: activeSubTab, payload: inputText }, { headers: { Authorization: `Bearer ${accessToken}` } });
      setAdversarialResult(response.data);
    } finally {
      setAdversarialLoading(false);
    }
  };

  useEffect(() => {
    if (!loading) return undefined;
    const timer = window.setTimeout(() => setScanStage('processing'), 450);
    return () => window.clearTimeout(timer);
  }, [loading]);

  const acceptFile = (file) => {
    if (!file) return;
    setSelectedFile(file);
    setInputText('');
    setDragActive(false);
  };

  const tabs = [
    { id: 'email', label: 'Email Phishing', icon: Mail },
    { id: 'email_file', label: 'EML Sender Inspection', icon: Mail },
    { id: 'sms', label: 'SMS / Social', icon: Mail },
    { id: 'deepfake', label: 'Deepfake Media', icon: Video },
    { id: 'image', label: 'Image Analysis', icon: Upload },
    { id: 'audio', label: 'Voice Analysis', icon: Video },
    { id: 'video', label: 'Video Analysis', icon: Video },
    { id: 'impersonation', label: 'Impersonation', icon: UserX },
    { id: 'url', label: 'Malicious URL', icon: Link },
    { id: 'website', label: 'Live Website', icon: Globe },
    { id: 'ato', label: 'Credential / ATO', icon: AlertTriangle },
    { id: 'auth_logs', label: 'Authentication Logs', icon: FileText },
    { id: 'system_logs', label: 'System Logs', icon: FileText },
    { id: 'network', label: 'Network Traffic', icon: FileText },
    { id: 'api_logs', label: 'API Logs', icon: FileText },
    { id: 'malware', label: 'Malware Indicators', icon: AlertTriangle },
    { id: 'exfiltration', label: 'Data Exfiltration', icon: AlertTriangle },
  ];

  const demoScenarios = [
    { name: 'Deepfake authority', category: 'deepfake', payload: 'Voice clone of the finance director uses synthetic speech to request an urgent transfer.' },
    { name: 'Behavioural ATO', category: 'ato', payload: JSON.stringify({ failed_attempts: 12, total_attempts: 15, distinct_accounts: 8, distinct_countries: 2, impossible_travel: true, new_device: true, mfa_denials: 4 }) },
    { name: 'URL + contact mismatch', category: 'url', payload: 'From: registrar@gmail.com urgently verify at https://micros0ft-login.xyz/auth?redirect=https://evil.example/login' },
    { name: 'UPI refund scam', category: 'sms', payload: 'Your UPI refund is pending. Scan this QR and approve the collect request of Rs 499 immediately to receive cashback.' },
    { name: 'Digital arrest call', category: 'impersonation', payload: 'CBI officer says you are under digital arrest. Do not disconnect the video call. Transfer money now to avoid jail.' },
  ];

  return (
    <div className="threat-inspector bg-cardBg border border-slate-700/60 rounded-xl p-6 shadow-lg">
      <div className="inspector-heading mb-6">
        <div className="inspector-title-block">
          <div className="inspector-kicker"><span className="live-pulse" /> MULTI-SOURCE ANALYSIS DESK</div>
          <h2 className="text-xl font-bold text-white">Detection Studio</h2>
          <p className="text-xs text-slate-400">
            Select an artifact channel, submit evidence, and receive a scored XAI assessment from the live engine.
          </p>
        </div>
        <div className="inspector-status"><span className="status-orb" /> ENGINE READY<strong>FastAPI / XAI</strong></div>
      </div>

      <div className="inspector-source-label"><span>01</span> Choose an analysis channel <small>{tabs.length} sources available</small></div>
      <div className="inspector-source-grid">
        {[
          ['email', 'Email', Mail], ['email_file', 'EML Inspect', Mail], ['url', 'URL', Link], ['website', 'Website', Globe], ['image', 'Image', Upload],
          ['audio', 'Audio', Video], ['video', 'Video', Video], ['system_logs', 'Logs', FileText],
        ].map(([id, label, Icon]) => <button key={id} type="button" onClick={() => { setActiveSubTab(id); setAnalysisResult(null); setSelectedFile(null); setInputText(''); }} className={`source-card ${activeSubTab === id ? 'source-card-active' : ''}`}><Icon size={17} /><span>{label}</span><small>{activeSubTab === id ? 'selected' : 'inspect'}</small></button>)}
      </div>

      <div className="inspector-demo mb-6 p-3 rounded-xl border border-amber-500/20 bg-amber-500/5">
        <div className="flex items-center gap-2 text-[10px] font-bold uppercase text-amber-300"><PlayCircle size={14} /> Three-minute demo scenarios</div>
        <div className="mt-2 flex flex-wrap gap-2">
          {demoScenarios.map((scenario) => <button key={scenario.category} type="button" onClick={() => { setActiveSubTab(scenario.category); setInputText(scenario.payload); setSelectedFile(null); setAnalysisResult(null); setError(null); }} className="px-2.5 py-1.5 rounded-lg border border-amber-500/20 bg-slate-900/60 text-[10px] text-slate-200 hover:border-amber-400/60">{scenario.name}</button>)}
        </div>
      </div>

      {/* Tabs */}
      <div className="inspector-advanced-tabs flex border-b border-slate-700 space-x-2 overflow-x-auto mb-6">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => {
                setActiveSubTab(tab.id);
                setAnalysisResult(null);
                setError(null);
                setSelectedFile(null);
              }}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition whitespace-nowrap ${
                isActive
                  ? 'border-cyan-500 text-cyan-400 bg-cyan-500/10 rounded-t-lg'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Icon size={16} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Input Form */}
      <div className="inspector-source-label"><span>02</span> Submit evidence <small>{activeSubTab.replace('_', ' ')} channel selected</small></div>
      <form onSubmit={handleAnalyze} className="inspector-form space-y-4">
        {['image', 'audio', 'video', 'deepfake', 'email_file'].includes(activeSubTab) ? (
          <div className={`dropzone border-2 border-dashed rounded-xl p-8 text-center ${dragActive ? 'dropzone-active' : ''}`} onDragOver={(event) => { event.preventDefault(); setDragActive(true); }} onDragLeave={() => setDragActive(false)} onDrop={(event) => { event.preventDefault(); acceptFile(event.dataTransfer.files?.[0]); }}>
            <Upload size={32} className="mx-auto text-slate-500 mb-2" />
            <p className="text-xs text-slate-300 font-medium">Upload Image, Audio, Video, or an EML message</p>
            <input
              type="file"
              className="hidden"
              id="mediaUpload"
              accept="image/*,audio/*,video/*,.eml,message/rfc822"
              onChange={(e) => acceptFile(e.target.files?.[0])}
            />
            <label
              htmlFor="mediaUpload"
              className="mt-4 inline-block px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg cursor-pointer border border-slate-700"
            >
              Select File
            </label>
            {selectedFile && (
              <p className="mt-3 text-[10px] text-cyan-400 truncate">Selected: {selectedFile.name}</p>
            )}
          </div>
        ) : (
          <div>
            <label className="inspector-input-label block text-xs font-semibold text-slate-400 mb-2">
              <span>Artifact content payload</span><small>Text, URL, email headers, or JSON telemetry</small>
            </label>
            <textarea
              rows={5}
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder={`Paste ${activeSubTab} payload, email headers, URL, or JSON logs here...`}
              className="w-full bg-darkBg border border-slate-700 rounded-xl p-3 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
            {activeSubTab === 'email' && inputText.trim() && (
              <div className="live-phishing-panel" aria-live="polite">
                <div className="live-phishing-heading"><span className="live-pulse" /> LIVE PHISHING SIGNAL {liveLoading && <Loader2 size={12} className="animate-spin" />}</div>
                {liveAssessment ? (
                  <div className="live-phishing-summary"><strong>{liveAssessment.risk_level} risk · {liveAssessment.risk_score}%</strong><span>{liveAssessment.xai_explanation}</span></div>
                ) : <span className="text-[10px] text-slate-500">Analyzing email indicators as you type...</span>}
              </div>
            )}
            {inputText.trim() && <div className="mt-3 flex items-center gap-3"><button type="button" onClick={runAdversarialTest} disabled={adversarialLoading} className="px-3 py-2 rounded-lg border border-amber-500/30 text-[10px] text-amber-200 disabled:opacity-50">{adversarialLoading ? 'Probing...' : 'Run adversarial self-test'}</button>{adversarialResult && <span className="text-[10px] text-slate-400">Confidence decay: <strong className="text-amber-300">{adversarialResult.confidence_decay}%</strong> · {adversarialResult.status}</span>}</div>}
          </div>
        )}

        <div className="scan-progress-row">
          {['scanning', 'processing', 'ready'].map((stage, index) => <span key={stage} className={scanStage === stage || (scanStage === 'ready' && index < 2) ? 'scan-step scan-step-active' : 'scan-step'}><i>{index + 1}</i>{stage === 'scanning' ? 'Scanning' : stage === 'processing' ? 'AI Processing' : 'XAI Ready'}</span>)}
        </div>
        <button
          type="submit"
          disabled={loading}
          className="w-full py-3 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded-xl text-xs flex items-center justify-center gap-2 transition shadow-lg disabled:opacity-50"
        >
          {loading ? (
            <>
              <Loader2 size={16} className="animate-spin" /> Querying FastAPI Models...
            </>
          ) : (
            <>
              <Search size={16} /> Run Multi-Engine Inspection
            </>
          )}
        </button>
      </form>

      {/* Error Alert */}
      {error && (
        <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-xs">
          {error}
        </div>
      )}

      {/* Live Results */}
      {analysisResult && (
        <div className="inspector-results mt-6 p-4 bg-slate-900/80 border border-slate-700 rounded-xl space-y-3 animate-in fade-in">
          <div className="inspector-source-label"><span>03</span> Assessment result <small>Explainable evidence returned</small></div>
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-400">FASTAPI ENGINE ASSESSMENT</span>
            <span
              className={`px-2.5 py-1 text-xs font-bold rounded-full border ${
                analysisResult.risk_level === 'Critical' || analysisResult.risk_level === 'High'
                  ? 'bg-red-500/20 text-red-400 border-red-500/40'
                  : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
              }`}
            >
              {analysisResult.risk_level} Risk ({analysisResult.risk_score}%)
            </span>
          </div>

          <div className="risk-meter"><div className="risk-meter-label"><span>Risk meter</span><strong>{analysisResult.risk_score}/100</strong></div><div className="risk-meter-track"><div className="risk-meter-fill" style={{ width: `${analysisResult.risk_score}%` }} /></div></div>

          <p className="text-xs text-slate-200 bg-darkBg p-3 rounded-lg border border-slate-800 leading-relaxed font-mono">
            {plainMode ? analysisResult.plain_language_explanation : analysisResult.xai_explanation}
          </p>
          <div className="flex items-center gap-3">
            <button type="button" onClick={() => setPlainMode((value) => !value)} className="px-3 py-2 rounded-lg border border-amber-500/30 text-[10px] text-amber-200">{plainMode ? 'Technical explanation' : 'Explain to my grandmother'}</button>
            {analysisResult.incident_id && <button type="button" onClick={downloadComplaintDraft} className="px-3 py-2 rounded-lg border border-emerald-500/30 text-[10px] text-emerald-200">Draft cybercrime.gov.in complaint</button>}
            <button type="button" onClick={askAnalystAssistant} disabled={assistantLoading} className="px-3 py-2 rounded-lg border border-cyan-500/30 text-[10px] text-cyan-200 disabled:opacity-50">
              {assistantLoading ? 'Generating analyst brief...' : 'Generate analyst brief'}
            </button>
            {assistantResult && <span className="text-[10px] text-slate-500">Source: {assistantResult.model}</span>}
          </div>
          {assistantResult && <div className="text-xs text-slate-200 bg-cyan-500/5 p-3 rounded-lg border border-cyan-500/20"><strong className="text-cyan-300">Analyst brief</strong><p className="mt-1">{assistantResult.summary}</p><ul className="mt-2 list-disc pl-4">{(assistantResult.next_steps || []).map((step) => <li key={step}>{step}</li>)}</ul>{assistantResult.privacy && <small className="mt-2 block text-slate-500">{assistantResult.privacy}</small>}</div>}
          {complaintDraft && <div className="text-[10px] text-emerald-200 bg-emerald-500/5 p-3 rounded-lg border border-emerald-500/20">Complaint draft ready for {complaintDraft.portal}. Verify details before submitting. Helpline: {complaintDraft.helpline}</div>}

          <div className="flex flex-wrap items-center gap-2 text-[10px]">
            <span className="px-2 py-1 rounded-md bg-cyan-500/10 border border-cyan-500/20 text-cyan-300">
              Engine: {analysisResult.detection_method || 'multi-engine'}
            </span>
            {(analysisResult.mitre_techniques || []).map((technique) => (
              <span key={technique} className="px-2 py-1 rounded-md bg-amber-500/10 border border-amber-500/20 text-amber-300">
                MITRE {technique}
              </span>
            ))}
          </div>

          <div className="space-y-1.5 pt-2">
            <span className="text-[10px] font-bold text-slate-400 uppercase">Engine Indicators</span>
            {analysisResult.indicators.map((ind, idx) => (
              <div key={idx} className="flex justify-between text-xs bg-slate-800/40 p-2 rounded border border-slate-800">
                <span className="text-slate-300">{ind.name}</span>
                <span className="font-mono text-cyan-400 font-bold">{ind.score}{ind.weight ? ` · weight ${ind.weight}` : ''}</span>
              </div>
            ))}
          </div>
          {analysisResult.qr_payload && <div className="text-xs text-amber-200 bg-amber-500/10 border border-amber-500/20 rounded-lg p-3">Decoded QR destination: <strong>{analysisResult.qr_payload}</strong></div>}
          {analysisResult.sender_authenticity && <div className="text-xs text-slate-300 bg-slate-800/40 border border-slate-700 rounded-lg p-3">Sender authenticity: From {analysisResult.sender_authenticity.from || 'unknown'} · Reply-To {analysisResult.sender_authenticity.reply_to || 'none'} · Return-Path {analysisResult.sender_authenticity.return_path || 'none'}</div>}
          <div className="pt-2">
            <span className="text-[10px] font-bold text-slate-400 uppercase">Extracted Threat Intelligence</span>
            <div className="mt-2 flex flex-wrap gap-2">
              {(analysisResult.iocs || []).map((ioc, index) => <button type="button" key={`${ioc.value}-${index}`} title={`${ioc.reputation || 'unknown'} reputation`} onClick={() => setInputText(ioc.value)} className="evidence-chip">{ioc.type}: {ioc.indicator || ioc.value} · {ioc.reputation || 'unknown'}</button>)}
              {!analysisResult.iocs?.length && <span className="text-[10px] text-slate-500">No IOCs extracted from this payload.</span>}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}