import React from 'react';
import { ChevronLeft, ChevronRight, LayoutDashboard, ShieldAlert, GitGraph, FileCheck, Bell, Settings, BrainCircuit, Orbit, Radar } from 'lucide-react';
export default function Sidebar({ activeTab, setActiveTab, collapsed, setCollapsed }) {
  const navItems = [
    { id: 'portal', label: 'Threat Radar', icon: Orbit, isPortal: true },
    { id: 'dashboard', label: 'Command Center', icon: LayoutDashboard },
    { id: 'inspector', label: 'Detection Studio', icon: ShieldAlert },
    { id: 'intelligence', label: 'Intelligence Operations', icon: BrainCircuit },
    { id: 'live', label: 'XDR Fusion', icon: Radar },
    { id: 'graph', label: 'Attack Graph', icon: GitGraph },
    { id: 'compliance', label: 'Compliance & Governance', icon: FileCheck },
    { id: 'notifications', label: 'Alert Inbox', icon: Bell },
    { id: 'admin', label: 'Administration', icon: Settings },
  ];

  return (
    <aside className={`app-sidebar ${collapsed ? 'sidebar-collapsed' : ''} p-4 hidden md:block`}>
      <div className="sidebar-top"><p className="sidebar-label">Operations</p><button type="button" className="sidebar-toggle" onClick={() => setCollapsed(!collapsed)} title="Collapse navigation">{collapsed ? <ChevronRight size={15} /> : <ChevronLeft size={15} />}</button></div>
      <nav className="space-y-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`nav-item w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-xs font-semibold transition ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
              }`}
            >
              <Icon size={18} />
              {!collapsed && <span>{item.label}</span>}
            </button>
          );
        })}
      </nav>
      {!collapsed && <div className="sidebar-footer"><span className="live-pulse" /> SOC link secured <strong>24/7</strong></div>}
    </aside>
  );
}