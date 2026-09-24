import React, { useState } from 'react';
import { Bell, Search, UserCheck, Orbit, LogOut } from 'lucide-react';

export default function Header({ userRole, unread = 0, onSearch, onOpenNotifications, onReturnToPortal, onLogout }) {
  const [query, setQuery] = useState('');
  const submitSearch = (event) => { event.preventDefault(); onSearch?.(query); };
  
  return (
    <header className="app-header px-6 py-3.5 flex items-center justify-between border-b border-cyan-500/15 bg-[#05111d]/90 backdrop-blur-md">
      {/* Brand Logo - Clickable to return to Portal */}
      <div 
        onClick={onReturnToPortal}
        className="flex items-center space-x-3 cursor-pointer group" 
        title="Return to CyberGuard Radar Portal"
      >
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-emerald-400/25 via-cyan-500/20 to-transparent border border-emerald-400/50 p-0.5 shadow-[0_0_15px_rgba(16,185,129,0.35)] flex items-center justify-center transition-transform group-hover:scale-105">
          <div className="w-full h-full rounded-[9px] bg-[#061826] flex items-center justify-center">
            <span className="font-mono font-black text-emerald-400 text-lg tracking-tighter">C</span>
          </div>
        </div>
        <div>
          <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-1.5">
            CyberGuard <span className="text-emerald-400 font-semibold">AI</span>
            <span className="ml-1.5 px-1.5 py-0.5 rounded text-[9px] font-mono border border-cyan-500/30 bg-cyan-950/40 text-cyan-300">
              v2.0
            </span>
          </h1>
          <p className="text-[10px] text-slate-400 font-mono">BPUT AI Cyber Defense & Incident Response Suite</p>
        </div>
      </div>

      {/* Center / Navigation Shortcuts */}
      <div className="hidden lg:flex items-center gap-2">
        <button
          onClick={onReturnToPortal}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-950/20 text-emerald-300 hover:text-white hover:border-emerald-400/50 hover:bg-emerald-900/30 text-xs font-mono transition-all"
        >
          <Orbit size={14} className="text-emerald-400 animate-spin" style={{ animationDuration: '12s' }} />
          <span>Threat Radar Portal</span>
        </button>
      </div>

      {/* System Status & Role Switcher */}
      <div className="flex items-center space-x-3.5">
        <form className="header-search" onSubmit={submitSearch}>
          <Search size={14} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search incidents, IOC..." />
        </form>

        <button type="button" className="notification-button" onClick={onOpenNotifications} title="Open notifications">
          <Bell size={16} />
          {unread > 0 && <span>{unread}</span>}
        </button>

        {/* Real-time Status Badge matching user's photo */}
        <div className="hidden sm:inline-flex items-center gap-2 px-3 py-1 rounded-full border border-emerald-500/30 bg-emerald-950/30 text-emerald-400 font-mono text-[11px] shadow-[0_0_12px_rgba(16,185,129,0.15)]">
          <span className="relative flex h-1.5 w-1.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
          </span>
          <span className="font-semibold">[ • ACTIVE ]</span>
        </div>

        {/* Role Badge */}
        <div className="role-chip">
          <UserCheck size={14} className="text-cyan-400" />
          <span className="text-slate-400 text-[11px]">Role:</span>
          <span className="font-mono text-[11px] font-bold text-cyan-300 uppercase">
            {userRole || 'Lead'}
          </span>
        </div>

        {onLogout && (
          <button
            onClick={onLogout}
            title="Sign out to Radar Portal"
            className="p-2 rounded-lg border border-slate-700/60 bg-slate-800/40 text-slate-400 hover:text-rose-400 hover:border-rose-500/30 transition-colors"
          >
            <LogOut size={15} />
          </button>
        )}
      </div>
    </header>
  );
}
