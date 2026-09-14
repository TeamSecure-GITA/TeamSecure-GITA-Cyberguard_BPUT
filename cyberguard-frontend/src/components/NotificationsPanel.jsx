import React, { useCallback, useEffect, useState } from 'react';
import axios from 'axios';
import { Bell, Check } from 'lucide-react';

export default function NotificationsPanel({ accessToken }) {
  const [items, setItems] = useState([]);
  const [error, setError] = useState(null);
  const load = useCallback(() => axios.get('http://127.0.0.1:8000/api/v1/notifications', { headers: { Authorization: `Bearer ${accessToken}` } }).then((response) => setItems(response.data.notifications || [])).catch(() => setError('Unable to load notifications.')), [accessToken]);
  useEffect(() => { load(); }, [load]);
  const markRead = async (id) => { await axios.patch(`http://127.0.0.1:8000/api/v1/notifications/${id}`, { read: true }, { headers: { Authorization: `Bearer ${accessToken}` } }); load(); };

  return <section className="bg-cardBg border border-slate-700/60 rounded-xl p-6 shadow-lg">
    <div className="flex items-center justify-between mb-5"><div><p className="eyebrow">Operator inbox</p><h2 className="text-xl font-bold text-white mt-1">Threat Notifications</h2></div><Bell className="text-cyan-400" size={22} /></div>
    {error && <p className="text-xs text-red-400 mb-3">{error}</p>}
    <div className="space-y-2">{items.map((item) => <div key={item.id} className={`flex items-start justify-between gap-4 p-4 rounded-lg border ${item.read ? 'border-slate-800 bg-slate-900/30' : 'border-cyan-500/30 bg-cyan-500/5'}`}><div><p className="text-sm font-semibold text-slate-200">{item.title}</p><p className="mt-1 text-xs text-slate-400">{item.message}</p><p className="mt-2 text-[10px] uppercase text-slate-500">{item.severity} · {item.created_at}</p></div>{!item.read && <button title="Mark as read" onClick={() => markRead(item.id)} className="p-2 rounded-md text-cyan-400 hover:bg-cyan-500/10"><Check size={16} /></button>}</div>)}{items.length === 0 && <p className="text-sm text-slate-500">No notifications yet.</p>}</div>
  </section>;
}
