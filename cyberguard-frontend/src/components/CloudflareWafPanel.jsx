import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Cloud, ShieldBan } from 'lucide-react';

const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function CloudflareWafPanel({ accessToken }) {
  const [status, setStatus] = useState(null);
  const [ip, setIp] = useState('');
  const [message, setMessage] = useState(null);
  const headers = { Authorization: `Bearer ${accessToken}` };
  useEffect(() => { axios.get(`${apiBaseUrl}/api/v1/admin/cloudflare/status`, { headers }).then((response) => setStatus(response.data)).catch(() => setStatus({ configured: false })); }, [accessToken]);
  const block = async (event) => { event.preventDefault(); if (!ip.trim()) return; try { const response = await axios.post(`${apiBaseUrl}/api/v1/admin/cloudflare/block-ip?ip_address=${encodeURIComponent(ip)}&reason=${encodeURIComponent('CyberGuard head-admin containment')}`, null, { headers }); setMessage(response.data.message || `Cloudflare block status: ${response.data.status}`); setIp(''); } catch (error) { setMessage(error.response?.data?.detail || 'Cloudflare WAF request failed.'); } };
  return <div className="bg-cardBg border border-slate-700/60 rounded-xl p-5"><h3 className="flex items-center gap-2 text-sm font-bold text-slate-200"><Cloud size={17} className="text-orange-300" /> Cloudflare WAF</h3><p className="mt-2 text-[10px] text-slate-500">{status?.configured ? `Connected to zone ${status.zone_id}` : 'Not configured. Add a zone-scoped API token and Zone ID to enable edge blocking.'}</p><form onSubmit={block} className="mt-4 flex gap-2"><input value={ip} onChange={(event) => setIp(event.target.value)} placeholder="IP address" className="flex-1 bg-slate-950/60 border border-slate-700 rounded-md p-2 text-xs text-white" /><button disabled={!status?.configured} className="px-3 rounded-md bg-orange-600 text-xs font-semibold text-white disabled:opacity-40"><ShieldBan size={14} className="inline mr-1" />Block</button></form>{message && <p className="mt-3 text-[10px] text-cyan-300">{message}</p>}</div>;
}
