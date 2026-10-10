import React, { useState } from 'react';
import axios from 'axios';
import { ScanLine, Upload } from 'lucide-react';

function errorMessage(error) {
  return error.response?.data?.detail || error.message || 'The analysis request failed.';
}

export default function TrustScanner({ apiBaseUrl, accessToken }) {
  const [payload, setPayload] = useState('');
  const [result, setResult] = useState(null);
  const [mediaResult, setMediaResult] = useState(null);
  const [comparisonResult, setComparisonResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const headers = { Authorization: `Bearer ${accessToken}` };

  const scan = async () => {
    if (!payload.trim()) return;
    setBusy(true);
    setError('');
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/scanner/scan`, { payload }, { headers });
      setResult(response.data);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setBusy(false);
    }
  };

  const inspectMedia = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setBusy(true);
    setError('');
    try {
      const form = new FormData();
      form.append('file', file);
      const response = await axios.post(`${apiBaseUrl}/api/v1/media/trust`, form, { headers });
      setMediaResult(response.data);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setBusy(false);
      event.target.value = '';
    }
  };

  const compareMedia = async (event) => {
    const files = Array.from(event.target.files || []);
    if (files.length < 2) {
      setError('Choose at least two media files to compare.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const form = new FormData();
      files.slice(0, 4).forEach((file) => form.append('files', file));
      const response = await axios.post(`${apiBaseUrl}/api/v1/roadmap/media-consistency`, form, { headers });
      setComparisonResult(response.data);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setBusy(false);
      event.target.value = '';
    }
  };

  return (
    <section className="glass-panel p-5">
      <div className="panel-heading">
        <div>
          <div className="eyebrow">QR / link / media scanner</div>
          <h3>Instant trust analysis</h3>
        </div>
        <ScanLine size={18} className="text-cyan-300" />
      </div>
      <textarea
        value={payload}
        onChange={(event) => setPayload(event.target.value)}
        placeholder="Paste a URL, email, or QR-decoded text"
        className="w-full mt-4 min-h-20 rounded-xl bg-slate-950 border border-slate-700 p-3 text-xs text-slate-200"
      />
      <div className="flex flex-wrap gap-2 mt-3">
        <button
          type="button"
          onClick={scan}
          disabled={busy || !payload.trim()}
          className="px-3 py-2 rounded-lg bg-cyan-600 text-xs font-semibold disabled:opacity-50"
        >
          {busy ? 'Scanning...' : 'Scan payload'}
        </button>
        <label className="px-3 py-2 rounded-lg border border-slate-700 text-xs text-slate-300 cursor-pointer">
          <Upload size={13} className="inline mr-1" /> Inspect image / audio / video
          <input type="file" accept="image/*,audio/*,video/*" onChange={inspectMedia} className="hidden" />
        </label>
        <label className="px-3 py-2 rounded-lg border border-amber-500/30 text-xs text-amber-200 cursor-pointer">
          Compare media channels
          <input type="file" multiple accept="image/*,audio/*,video/*" onChange={compareMedia} className="hidden" />
        </label>
      </div>
      {error && <p role="alert" className="mt-3 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">{error}</p>}
      {result && (
        <div className="mt-4 p-3 rounded-xl border border-slate-800 bg-slate-900/70 text-xs">
          <strong className={result.safe ? 'text-emerald-300' : 'text-rose-300'}>
            {result.safe ? 'LOW RISK' : 'THREAT SIGNAL DETECTED'} · risk {result.risk_score}/99
          </strong>
          <p className="text-slate-400 mt-1">Threat genome: {result.genome}</p>
          {result.results.map((item) => (
            <p key={item.value} className="text-slate-300 mt-1">{item.value} - {item.reputation} (risk {item.risk_score}/99)</p>
          ))}
        </div>
      )}
      {mediaResult && (
        <div className="mt-4 p-3 rounded-xl border border-slate-800 bg-slate-900/70 text-xs">
          <strong className="text-cyan-300">
            {mediaResult.media_type.toUpperCase()} DETECTOR RISK: {mediaResult.risk_score}/99
          </strong>
          <p className="text-slate-400 mt-1">Analysis method: {mediaResult.method}</p>
          <p className="text-slate-500 mt-1">{mediaResult.calibration}</p>
          {(mediaResult.reasons || []).map((reason) => <p key={reason} className="text-slate-300 mt-1">{reason}</p>)}
        </div>
      )}
      {comparisonResult && (
        <div className="mt-4 p-3 rounded-xl border border-amber-500/20 bg-amber-500/5 text-xs">
          <strong className="text-amber-200">Cross-modal {comparisonResult.status}: inverse-risk proxy {comparisonResult.authenticity_score}/100</strong>
          <p className="text-slate-400 mt-1">Heuristic consistency {comparisonResult.consistency_score}/100 across {comparisonResult.media_count} channels; not a calibrated probability.</p>
        </div>
      )}
    </section>
  );
}
