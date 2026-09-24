import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';

const dhcpAssets = [
  { ip: '192.168.1.10', hostname: 'Admin-Workstation', mac: '00:1A:2B:3C:4D:5E', status: 'trusted' },
  { ip: '192.168.1.25', hostname: 'Finance-Server', mac: 'A1:B2:C3:D4:E5:F6', status: 'trusted' },
  { ip: '192.168.1.42', hostname: 'Faculty-Laptop', mac: '88:77:66:55:44:33', status: 'trusted' },
  { ip: '192.168.1.99', hostname: 'Unknown-Kali-Linux', mac: '74:E1:B2:8F:44:9A', status: 'quarantined' },
];

export default function SecurityFusionCenter({ apiBaseUrl, accessToken }) {
  const [logs, setLogs] = useState([]);
  const [authResult, setAuthResult] = useState({ auth_status: 'IDLE' });
  const [form, setForm] = useState({
    username: 'user_admin',
    password: 'admin123',
    source_ip: '192.168.1.99',
    service_provider_app: 'CYBERGUARD SOC',
  });
  const [seedAttempted, setSeedAttempted] = useState(false);

  const loadLogs = async () => {
    try {
      const response = await axios.get(`${apiBaseUrl}/api/v1/siem/logs`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const events = response.data.events || [];
      if (!events.length && !seedAttempted) {
        setSeedAttempted(true);
        const seeded = await axios.post(`${apiBaseUrl}/api/v1/siem/demo-seed`, {}, { headers: { Authorization: `Bearer ${accessToken}` } });
        setLogs(seeded.data.events || []);
      } else {
        setLogs(events);
      }
    } catch {
      setLogs([
        {
          timestamp: new Date().toISOString(),
          source_ip: '192.168.1.99',
          hostname: 'Unknown-Kali-Linux',
          event: 'credential-stuffing',
          severity: 'CRITICAL',
          details: 'Fallback SIEM feed active during backend warm-up.',
        },
      ]);
    }
  };

  useEffect(() => {
    if (!accessToken) return undefined;
    loadLogs();
    const interval = window.setInterval(loadLogs, 15000);
    return () => window.clearInterval(interval);
  }, [apiBaseUrl, accessToken, seedAttempted]);

  const riskCount = useMemo(() => logs.filter((entry) => ['HIGH', 'CRITICAL'].includes(entry.severity)).length, [logs]);

  const runAuthenticationCheck = async () => {
    try {
      const response = await axios.post(
        `${apiBaseUrl}/api/v1/idp/authenticate`,
        form,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      setAuthResult(response.data);
    } catch {
      setAuthResult({
        auth_status: 'DENIED',
        reason: 'Identity Provider simulation unavailable',
      });
    }
  };

  return (
    <section className="glass-panel p-5 border border-cyan-500/20 bg-[radial-gradient(circle_at_top,_rgba(12,74,110,0.35),_rgba(2,6,23,0.96)_45%)] shadow-[0_0_30px_rgba(34,211,238,0.16)]">
      <div className="panel-heading">
        <div>
          <div className="eyebrow text-cyan-300 tracking-[0.2em] uppercase">XDR Fusion Center</div>
          <h3 className="text-cyan-100">SIEM + DHCP + IdP live control stack</h3>
        </div>
        <span className="rounded-full border border-cyan-400/40 bg-cyan-500/10 px-3 py-1 text-xs font-semibold text-cyan-300">
          {riskCount} active escalations
        </span>
      </div>

      <div className="mt-5 grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="rounded-2xl border border-cyan-500/20 bg-slate-950/70 p-4 shadow-[inset_0_0_20px_rgba(34,211,238,0.06)]">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-sm font-semibold text-slate-100">DHCP asset registry</h4>
            <span className="rounded-full border border-emerald-400/30 bg-emerald-500/10 px-2 py-1 text-[10px] text-emerald-300">live lease view</span>
          </div>
          <div className="space-y-2">
            {dhcpAssets.map((asset) => (
              <div key={asset.ip} className="flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/80 px-3 py-2 transition hover:border-cyan-500/30">
                <div>
                  <div className="text-xs font-semibold text-slate-100">{asset.hostname}</div>
                  <div className="text-[10px] text-slate-400">{asset.ip} • {asset.mac}</div>
                </div>
                <span className={`rounded-full px-2 py-1 text-[9px] font-semibold ${asset.status === 'quarantined' ? 'border border-rose-400/40 bg-rose-500/10 text-rose-300' : 'border border-emerald-400/30 bg-emerald-500/10 text-emerald-300'}`}>
                  {asset.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-2xl border border-violet-500/20 bg-slate-950/70 p-4 shadow-[inset_0_0_20px_rgba(168,85,247,0.06)]">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-sm font-semibold text-slate-100">IdP session verification</h4>
            <span className="rounded-full border border-violet-400/30 bg-violet-500/10 px-2 py-1 text-[10px] text-violet-300">zero-trust policy</span>
          </div>
          <div className="space-y-3">
            <input
              value={form.username}
              onChange={(event) => setForm({ ...form, username: event.target.value })}
              className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-100 outline-none ring-0 placeholder:text-slate-500 focus:border-cyan-400"
              placeholder="Username"
            />
            <input
              value={form.password}
              onChange={(event) => setForm({ ...form, password: event.target.value })}
              type="password"
              className="w-full rounded-xl border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400"
              placeholder="Password"
            />
            <div className="grid grid-cols-2 gap-2">
              <input
                value={form.source_ip}
                onChange={(event) => setForm({ ...form, source_ip: event.target.value })}
                className="rounded-xl border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400"
                placeholder="Source IP"
              />
              <input
                value={form.service_provider_app}
                onChange={(event) => setForm({ ...form, service_provider_app: event.target.value })}
                className="rounded-xl border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-100 outline-none placeholder:text-slate-500 focus:border-cyan-400"
                placeholder="App"
              />
            </div>
            <button type="button" onClick={runAuthenticationCheck} className="w-full rounded-xl bg-gradient-to-r from-cyan-400 to-violet-500 px-3 py-2 text-xs font-semibold text-slate-950 shadow-[0_0_20px_rgba(34,211,238,0.35)] hover:brightness-110">
              Validate identity context
            </button>
            <div className={`rounded-xl border p-3 text-[11px] ${authResult.auth_status === 'BLOCKED' ? 'border-rose-400/40 bg-rose-500/10 text-rose-200' : authResult.auth_status === 'SUCCESS' ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-200' : 'border-slate-700 bg-slate-900/80 text-slate-300'}`}>
              <div className="font-medium text-slate-100">Status: {authResult.auth_status}</div>
              <div className="mt-1 text-slate-200">{authResult.reason || authResult.message || 'Waiting for an identity check.'}</div>
            </div>
          </div>
        </div>
      </div>

      <div className="mt-5 rounded-2xl border border-amber-500/20 bg-slate-950/70 p-4 shadow-[inset_0_0_20px_rgba(251,191,36,0.06)]">
        <div className="flex items-center justify-between mb-3">
          <h4 className="text-sm font-semibold text-slate-100">Live SIEM correlation feed</h4>
          <button type="button" onClick={loadLogs} className="rounded-full border border-cyan-400/40 bg-cyan-500/10 px-2 py-1 text-[10px] font-semibold text-cyan-300">Refresh</button>
        </div>
        <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
          {logs.length === 0 ? (
            <div className="text-xs text-slate-400">No SIEM events currently ingested.</div>
          ) : (
            logs.map((entry, index) => (
              <div key={`${entry.timestamp}-${index}`} className={`rounded-xl border p-3 ${entry.severity === 'CRITICAL' ? 'border-rose-400/30 bg-rose-500/10' : entry.severity === 'HIGH' ? 'border-orange-400/30 bg-orange-500/10' : 'border-emerald-400/30 bg-emerald-500/10'}`}>
                <div className="flex items-center justify-between gap-3">
                  <div className="text-[11px] text-slate-100"><strong>{entry.hostname}</strong> • {entry.source_ip}</div>
                  <span className={`rounded-full px-2 py-1 text-[9px] font-semibold ${entry.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-200' : entry.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-200' : 'bg-emerald-500/20 text-emerald-200'}`}>
                    {entry.severity}
                  </span>
                </div>
                <div className="mt-1 text-[10px] text-slate-300">{entry.event} • {entry.timestamp}</div>
                <div className="mt-1 text-[10px] text-slate-200">{entry.details}</div>
              </div>
            ))
          )}
        </div>
      </div>
    </section>
  );
}
