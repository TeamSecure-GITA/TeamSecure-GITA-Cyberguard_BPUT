import React, { useState } from 'react';
import { Bell, Search, Shield, Radio, UserCheck } from 'lucide-react';

export default function Header({ userRole, unread = 0, onSearch, onOpenNotifications }) {
  const [query, setQuery] = useState('');
  const submitSearch = (event) => { event.preventDefault(); onSearch?.(query); };
  return (
    <header className="app-header px-6 py-4 flex items-center justify-between">
      {/* Brand Logo */}
      <div className="flex items-center space-x-3">
        <div className="brand-mark">
          <Shield size={24} />
        </div>
        <div>
          <h1 className="text-xl font-black tracking-wider text-white flex items-center gap-2">
            CYBERGUARD <span className="brand-version">SOC / v2.0</span>
          </h1>
          <p className="text-[10px] text-slate-400 font-mono">BPUT AI Cyber Defense & Incident Response Suite</p>
        </div>
      </div>

      {/* System Status & Role Switcher */}
      <div className="flex items-center space-x-4">
        <form className="header-search" onSubmit={submitSearch}><Search size={14} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search incidents, IOC..." /></form>
        <button type="button" className="notification-button" onClick={onOpenNotifications} title="Open notifications"><Bell size={17} />{unread > 0 && <span>{unread}</span>}</button>
        <div className="header-status">
          <Radio size={14} className="text-emerald-400 animate-pulse" />
          <span className="text-slate-300">Engine:</span>
          <span className="text-emerald-400 font-bold">ONLINE</span>
        </div>

        {/* Role Toggle Switch */}
        <div className="role-chip">
          <UserCheck size={14} className="text-cyan-400" />
          <span className="text-slate-400">Role:</span>
          <select
            value={userRole}
            disabled
            className="bg-transparent text-cyan-400 font-bold focus:outline-none cursor-pointer"
          >
            <option value="analyst" className="bg-slate-900 text-slate-200">Tier 1 Analyst (View Only)</option>
            <option value="lead" className="bg-slate-900 text-cyan-400">Senior SOC Lead (Full Access)</option>
            <option value="admin" className="bg-slate-900 text-emerald-400">Platform Administrator</option>
          </select>
        </div>
      </div>
    </header>
  );
}