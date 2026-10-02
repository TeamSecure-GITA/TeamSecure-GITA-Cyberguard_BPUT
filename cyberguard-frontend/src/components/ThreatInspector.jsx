import React, { useEffect, useState } from 'react';
import { Mail, Video, Link, FileText, UserX, AlertTriangle, Upload, Search, Loader2, PlayCircle, Globe, Trash2 } from 'lucide-react';
import axios from 'axios';
import { getApiBaseUrl } from '../apiConfig';

export default function ThreatInspector({ accessToken }) {
  const [activeSubTab, setActiveSubTab] = useState('email');
  const [incidentCountry, setIncidentCountry] = useState('');
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [scanStage, setScanStage] = useState('idle');
  const [dragActive, setDragActive] = useState(false);
  const [livePreview, setLivePreview] = useState({ payload: null, assessment: null });
  const [liveLoadingFor, setLiveLoadingFor] = useState(null);
  const [adversarialResult, setAdversarialResult] = useState(null);
  const [adversarialLoading, setAdversarialLoading] = useState(false);
  const [assistantResult, setAssistantResult] = useState(null);
  const [assistantLoading, setAssistantLoading] = useState(false);
  const [plainMode, setPlainMode] = useState(false);
  const [complaintDraft, setComplaintDraft] = useState(null);
  const [knownContacts, setKnownContacts] = useState([]);
  const [selectedContactId, setSelectedContactId] = useState('');
  const [contactName, setContactName] = useState('');
  const [contactIdentifiers, setContactIdentifiers] = useState('');
  const [contactSamples, setContactSamples] = useState('');
  const [contactBusy, setContactBusy] = useState(false);
  const [contactError, setContactError] = useState('');

  const apiBaseUrl = getApiBaseUrl();
  const fileAnalysisTabs = ['image', 'audio', 'video', 'deepfake', 'email_file', 'malware'];
  const showLivePreview = activeSubTab === 'email' && Boolean(inputText.trim());
  const liveAssessment = showLivePreview && livePreview.payload === inputText ? livePreview.assessment : null;
  const liveLoading = showLivePreview && liveLoadingFor === inputText;

  useEffect(() => {
    if (!showLivePreview) return undefined;

    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      setLiveLoadingFor(inputText);
      try {
        const response = await axios.post(`${apiBaseUrl}/api/v1/analyze/preview`, {
          category: 'email',
          payload: inputText,
        }, { headers: { Authorization: `Bearer ${accessToken}` }, signal: controller.signal });
        setLivePreview({ payload: inputText, assessment: response.data?.assessment || null });
      } catch (previewError) {
        if (!axios.isCancel(previewError)) setLivePreview({ payload: inputText, assessment: null });
      } finally {
        if (!controller.signal.aborted) setLiveLoadingFor((payload) => payload === inputText ? null : payload);
      }
    }, 500);

    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [showLivePreview, inputText, accessToken, apiBaseUrl]);

  useEffect(() => {
    if (activeSubTab !== 'impersonation' || !accessToken) return undefined;
    let active = true;
    axios.get(`${apiBaseUrl}/api/v1/known-contacts`, { headers: { Authorization: `Bearer ${accessToken}` } })
      .then((response) => {
        if (active) {
          setContactError('');
          setKnownContacts(response.data.contacts || []);
        }
      })
      .catch((requestError) => {
        if (active) setContactError(requestError.response?.data?.detail || 'Known contact profiles are unavailable.');
      });
    return () => { active = false; };
  }, [activeSubTab, accessToken, apiBaseUrl]);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    const hasFileToAnalyze = (fileAnalysisTabs.includes(activeSubTab) || activeSubTab === 'network') && selectedFile;
    if (!inputText.trim() && !hasFileToAnalyze) return;

    setLoading(true);
    setScanStage('scanning');
    setError(null);
    setAnalysisResult(null);

    try {
      const config = { headers: { Authorization: `Bearer ${accessToken}` } };
      let response;
      if (activeSubTab === 'website') {
        response = await axios.post(`${apiBaseUrl}/api/v1/analyze/website`, { url: inputText, metadata: incidentCountry ? { country: incidentCountry } : undefined }, config);
      } else if (hasFileToAnalyze) {
        const formData = new FormData();
        formData.append('category', activeSubTab === 'email_file' ? 'email' : activeSubTab);
        formData.append('file', selectedFile);
        if (incidentCountry) formData.append('metadata', JSON.stringify({ country: incidentCountry }));
        response = await axios.post(`${apiBaseUrl}/api/v1/analyze/file`, formData, config);
      } else {
        const metadata = {
          ...(incidentCountry ? { country: incidentCountry } : {}),
          ...(activeSubTab === 'impersonation' && selectedContactId ? { known_contact_id: Number(selectedContactId) } : {}),
        };
        response = await axios.post(`${apiBaseUrl}/api/v1/analyze`, {
          category: activeSubTab,
          payload: inputText,
          metadata: Object.keys(metadata).length ? metadata : undefined,
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

  const saveKnownContact = async () => {
    setContactBusy(true);
    setContactError('');
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/known-contacts`, {
        name: contactName,
        identifiers: contactIdentifiers.split(/[,;\n]/).map((value) => value.trim()).filter(Boolean),
        sample_messages: contactSamples.split(/\r?\n\s*\r?\n/).map((value) => value.trim()).filter(Boolean),
      }, { headers: { Authorization: `Bearer ${accessToken}` } });
      setKnownContacts((current) => [...current.filter((contact) => contact.id !== response.data.id), response.data]);
      setSelectedContactId(String(response.data.id));
      setContactName('');
      setContactIdentifiers('');
      setContactSamples('');
    } catch (requestError) {
      setContactError(requestError.response?.data?.detail || 'Could not save the contact profile.');
    } finally {
      setContactBusy(false);
    }
  };

  const deleteKnownContact = async () => {
    if (!selectedContactId) return;
    setContactBusy(true);
    setContactError('');
    try {
      await axios.delete(`${apiBaseUrl}/api/v1/known-contacts/${selectedContactId}`, { headers: { Authorization: `Bearer ${accessToken}` } });
      setKnownContacts((current) => current.filter((contact) => String(contact.id) !== selectedContactId));
      setSelectedContactId('');
    } catch (requestError) {
      setContactError(requestError.response?.data?.detail || 'Could not delete the contact profile.');
    } finally {
      setContactBusy(false);
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
      {activeSubTab === 'impersonation' && (
        <section className="mb-4 space-y-3 border-y border-slate-800 py-4">
          <div className="flex items-end gap-2">
            <label className="grid flex-1 gap-1 text-xs text-slate-400">Known contact
              <select value={selectedContactId} onChange={(event) => setSelectedContactId(event.target.value)} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200">
                <option value="">Keyword screening only</option>
                {knownContacts.map((contact) => <option key={contact.id} value={contact.id}>{contact.name} · {contact.sample_count} samples</option>)}
              </select>
            </label>
            <button type="button" onClick={deleteKnownContact} disabled={!selectedContactId || contactBusy} title="Delete selected contact profile" aria-label="Delete selected contact profile" className="grid h-9 w-9 place-items-center rounded-lg border border-slate-700 text-slate-300 hover:border-rose-500 hover:text-rose-300 disabled:opacity-40"><Trash2 size={15} /></button>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <label className="grid gap-1 text-xs text-slate-400">Contact name
              <input value={contactName} onChange={(event) => setContactName(event.target.value)} maxLength={120} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200" />
            </label>
            <label className="grid gap-1 text-xs text-slate-400">Known identifiers
              <input value={contactIdentifiers} onChange={(event) => setContactIdentifiers(event.target.value)} placeholder="Email, handle, or phone" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200" />
            </label>
          </div>
          <label className="grid gap-1 text-xs text-slate-400">Writing samples
            <textarea rows={3} value={contactSamples} onChange={(event) => setContactSamples(event.target.value)} placeholder="Add at least three messages, separated by blank lines" className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200" />
          </label>
          <div className="flex flex-wrap items-center gap-3">
            <button type="button" onClick={saveKnownContact} disabled={contactBusy || !contactName.trim() || !contactIdentifiers.trim() || contactSamples.split(/\r?\n\s*\r?\n/).filter((value) => value.trim()).length < 3} className="rounded-lg border border-cyan-700 px-3 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-950 disabled:opacity-40">{contactBusy ? 'Saving...' : 'Save contact profile'}</button>
            {contactError && <span role="alert" className="text-xs text-rose-300">{contactError}</span>}
          </div>
        </section>
      )}
      <label className="mb-3 grid max-w-xs gap-1 text-xs text-slate-400">Incident residency
        <select value={incidentCountry} onChange={(event) => setIncidentCountry(event.target.value)} className="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-200">
          <option value="">Not specified</option><option value="IN">India</option><option value="US">United States</option><option value="EU">European Union</option><option value="GB">United Kingdom</option>
        </select>
      </label>
      <form onSubmit={handleAnalyze} className="inspector-form space-y-4">
        {fileAnalysisTabs.includes(activeSubTab) || (activeSubTab === 'network' && selectedFile) ? (
          <div className={`dropzone border-2 border-dashed rounded-xl p-8 text-center ${dragActive ? 'dropzone-active' : ''}`} onDragOver={(event) => { event.preventDefault(); setDragActive(true); }} onDragLeave={() => setDragActive(false)} onDrop={(event) => { event.preventDefault(); acceptFile(event.dataTransfer.files?.[0]); }}>
            <Upload size={32} className="mx-auto text-slate-500 mb-2" />
            <p className="text-xs text-slate-300 font-medium">{activeSubTab === 'malware' ? 'Upload a file for YARA signature triage' : activeSubTab === 'network' ? 'Upload a PCAP or PCAPNG capture for flow analysis' : 'Upload Image, Audio, Video, or an EML message'}</p>
            <input
              type="file"
              className="hidden"
              id="mediaUpload"
              accept={activeSubTab === 'malware' ? '*/*' : activeSubTab === 'network' ? '.pcap,.pcapng,application/vnd.tcpdump.pcap' : 'image/*,audio/*,video/*,.eml,message/rfc822'}
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
            {activeSubTab === 'network' && (
              <label className="mt-3 grid max-w-md gap-1 text-xs text-slate-400">PCAP / PCAPNG capture
                <input type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" onChange={(event) => acceptFile(event.target.files?.[0])} className="text-xs text-slate-300 file:mr-3 file:rounded-lg file:border file:border-slate-700 file:bg-slate-900 file:px-3 file:py-2 file:text-slate-200" />
              </label>
            )}
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
          {analysisResult.ocr_analysis && (
            <div className="rounded-lg border border-sky-800/60 bg-sky-950/20 p-3 text-xs text-sky-100">
              <strong>Image OCR · {analysisResult.ocr_analysis.status.replaceAll('_', ' ')}</strong>
              {analysisResult.ocr_analysis.status === 'text_detected' ? (
                <p className="mt-1 text-[11px] text-sky-200/80">{analysisResult.ocr_analysis.character_count} characters analyzed · text risk {analysisResult.ocr_analysis.risk_score}/100 · raw text is not retained in this result.</p>
              ) : analysisResult.ocr_analysis.reason ? <p className="mt-1 text-[11px] text-sky-200/80">{analysisResult.ocr_analysis.reason}</p> : null}
              {(analysisResult.ocr_analysis.brand_domain_mismatches || []).map((mismatch) => (
                <p key={`${mismatch.brand}-${mismatch.observed_domain}`} className="mt-2 text-[11px] text-rose-200">
                  {mismatch.brand} login claim · observed {mismatch.observed_domain} · expected {mismatch.expected_domain}
                </p>
              ))}
            </div>
          )}
          {analysisResult.network_capture_summary && (
            <div className="rounded-lg border border-cyan-800/60 bg-cyan-950/20 p-3 text-xs text-cyan-100">
              <strong>Network capture · {analysisResult.network_capture_summary.packet_count} packets</strong>
              <p className="mt-1 text-[11px] text-cyan-200/80">Reconstructed {analysisResult.network_capture_summary.flow_count} TCP/UDP flows for network risk analysis.</p>
            </div>
          )}
          {analysisResult.known_contact_comparison && (
            <div className="rounded-lg border border-amber-700/50 bg-amber-950/20 p-3 text-xs text-amber-100">
              <strong>{analysisResult.known_contact_comparison.contact_name}</strong>
              <span> · sender {analysisResult.known_contact_comparison.sender_match === null ? 'not present' : analysisResult.known_contact_comparison.sender_match ? 'matches' : 'does not match'} · vocabulary similarity {Math.round(analysisResult.known_contact_comparison.vocabulary_similarity * 100)}%</span>
              <p className="mt-1 text-[11px] text-amber-200/80">{analysisResult.known_contact_comparison.caveat}</p>
            </div>
          )}
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
              <div key={idx} className="text-xs bg-slate-800/40 p-2 rounded border border-slate-800">
                <div className="flex justify-between gap-3">
                  <span className="text-slate-300">{ind.name}</span>
                  <span className="font-mono text-cyan-400 font-bold">{ind.score}{ind.weight ? ` · weight ${ind.weight}` : ''}</span>
                </div>
                {ind.feature_attribution?.status === 'available' && (
                  <div className="mt-2 border-t border-slate-700/70 pt-2" aria-label="Local text model feature attribution">
                    <p className="text-[10px] text-slate-400">{ind.feature_attribution.interpretation}</p>
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      {ind.feature_attribution.features.map((feature, featureIndex) => (
                        <span key={`${feature.feature}-${featureIndex}`} className={`rounded px-1.5 py-1 text-[10px] ${feature.effect === 'suspicious' ? 'bg-rose-500/10 text-rose-200' : 'bg-emerald-500/10 text-emerald-200'}`}>
                          {feature.feature} · {feature.effect} {feature.logit_contribution}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
          {analysisResult.qr_payload && <div className="text-xs text-amber-200 bg-amber-500/10 border border-amber-500/20 rounded-lg p-3">Decoded QR destination: <strong>{analysisResult.qr_payload}</strong></div>}
          {analysisResult.sender_authenticity && <div className="text-xs text-slate-300 bg-slate-800/40 border border-slate-700 rounded-lg p-3">Sender authenticity: From {analysisResult.sender_authenticity.from || 'unknown'} · Reply-To {analysisResult.sender_authenticity.reply_to || 'none'} · Return-Path {analysisResult.sender_authenticity.return_path || 'none'}</div>}
          {(analysisResult.email_attachments || []).length > 0 && (
            <div className="rounded-lg border border-amber-800/60 bg-amber-950/20 p-3 text-xs text-amber-100">
              <strong>Email attachment inspection</strong>
              <div className="mt-2 space-y-2">
                {analysisResult.email_attachments.map((attachment) => (
                  <div key={`${attachment.filename}-${attachment.sha256}`} className="border-t border-amber-900/50 pt-2">
                    <div className="flex flex-wrap justify-between gap-2">
                      <span>{attachment.filename} · {attachment.size_bytes} bytes</span>
                      <span>{attachment.malware_scan?.status || 'signature scan unavailable'}</span>
                    </div>
                    <p className="mt-1 text-[10px] text-amber-200/70">
                      {attachment.malware_scan?.reasons?.join(' ') || 'No malware scan result was returned.'}
                    </p>
                    {attachment.malware_scan?.archive_scan && (
                      <p className="mt-1 text-[10px] text-amber-200/70">
                        ZIP contents: {attachment.malware_scan.archive_scan.status} · {attachment.malware_scan.archive_scan.entries_scanned} entries scanned · {attachment.malware_scan.archive_scan.skipped_count ?? attachment.malware_scan.archive_scan.skipped_entries.length} skipped
                      </p>
                    )}
                  </div>
                ))}
              </div>
              <p className="mt-2 text-[10px] text-amber-200/70">A YARA no-match result is not proof that an attachment is benign.</p>
            </div>
          )}
          {analysisResult.sender_identity_verification && <div className="text-xs text-slate-200 bg-slate-800/40 border border-slate-700 rounded-lg p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <strong>Sender identity: {analysisResult.sender_identity_verification.status.replaceAll('_', ' ')}</strong>
              <span className={analysisResult.sender_identity_verification.status === 'verified' ? 'text-emerald-300' : 'text-amber-300'}>risk {analysisResult.sender_identity_verification.risk_score}/100</span>
            </div>
            <div className="mt-1 text-slate-400">From domain: {analysisResult.sender_identity_verification.from_domain || 'unavailable'} · Authentication server: {analysisResult.sender_identity_verification.authserv_id || 'unreported'} ({analysisResult.sender_identity_verification.authentication_trusted ? 'trusted' : 'untrusted'})</div>
          </div>}
          {analysisResult.login_baseline && <div className="border-t border-slate-800 pt-3 text-xs text-slate-300">
            <strong className="text-slate-200">Login baseline: {analysisResult.login_baseline.status}</strong>
            <span className="ml-2 text-slate-500">{analysisResult.login_baseline.samples} successful samples{analysisResult.login_baseline.signals ? ` · ${analysisResult.login_baseline.signals} deviations` : ''}</span>
          </div>}
          {analysisResult.geoip && <div className="text-xs text-slate-400">GeoIP: {analysisResult.geoip.country || 'not available'} · {analysisResult.geoip.status.replaceAll('_', ' ')}</div>}
          {analysisResult.malware_scan && <div className="border-t border-slate-800 pt-3 space-y-1 text-xs">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1"><strong className="text-slate-200">YARA file scan</strong><span className={analysisResult.malware_scan.matches?.length ? 'text-rose-300' : 'text-amber-300'}>{analysisResult.malware_scan.status.replaceAll('_', ' ')}</span><span className="text-slate-500">{analysisResult.malware_scan.engine}</span></div>
            <div className="break-all font-mono text-[10px] text-slate-500">SHA-256 {analysisResult.malware_scan.sha256}</div>
            {(analysisResult.malware_scan.matches || []).map((match, index) => <div key={`${match.rule}-${match.archive_path || index}`} className="text-rose-200">{match.rule} · risk {match.meta?.risk_score ?? '--'}{match.archive_path ? ` · ${match.archive_path}` : ''}</div>)}
            {(analysisResult.malware_scan.reasons || []).map((reason) => <p key={reason} className="text-slate-400">{reason}</p>)}
            {analysisResult.malware_scan.archive_scan && <p className="text-slate-400">ZIP contents: {analysisResult.malware_scan.archive_scan.status} · {analysisResult.malware_scan.archive_scan.entries_scanned} entries scanned · {analysisResult.malware_scan.archive_scan.skipped_count ?? analysisResult.malware_scan.archive_scan.skipped_entries.length} skipped</p>}
          </div>}
          {analysisResult.website_inspection && <div className="border-t border-slate-800 pt-3 space-y-1 text-xs">
            <strong className="text-slate-200">Website identity and domain checks</strong>
            <div className="text-slate-400">TLS: {analysisResult.website_inspection.tls_certificate?.status || 'not checked'}{analysisResult.website_inspection.tls_certificate?.issuer ? ` · ${analysisResult.website_inspection.tls_certificate.issuer}` : ''}{analysisResult.website_inspection.tls_certificate?.days_remaining != null ? ` · ${analysisResult.website_inspection.tls_certificate.days_remaining} days remaining` : ''}</div>
            <div className="text-slate-400">Domain registration: {analysisResult.website_inspection.domain_registration?.status || 'not checked'}{analysisResult.website_inspection.domain_registration?.age_days != null ? ` · ${analysisResult.website_inspection.domain_registration.age_days} days old` : ''}</div>
            <div className="text-slate-400">Certificate Transparency: {analysisResult.website_inspection.certificate_transparency?.status || 'not checked'}{analysisResult.website_inspection.certificate_transparency?.available ? ` · ${analysisResult.website_inspection.certificate_transparency.certificate_count} records · ${analysisResult.website_inspection.certificate_transparency.matching_names.join(', ') || 'no matching names'}` : ''}</div>
            {!!analysisResult.website_inspection.claimed_brands?.length && <div className="text-slate-400">Page claims: {analysisResult.website_inspection.claimed_brands.join(', ')}{analysisResult.website_inspection.brand_mismatches?.length ? ` · mismatched domain: ${analysisResult.website_inspection.brand_mismatches.join(', ')}` : ''}</div>}
            {!!analysisResult.website_inspection.cross_origin_form_actions?.length && <div className="text-rose-300">Credential form submits to: {analysisResult.website_inspection.cross_origin_form_actions.join(', ')}</div>}
            {(analysisResult.website_inspection.findings || []).map((finding) => <p key={finding} className="text-amber-200">{finding}</p>)}
          </div>}
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