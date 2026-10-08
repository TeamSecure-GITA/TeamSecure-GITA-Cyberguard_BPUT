import React from 'react';
import { 
  ChevronLeft, 
  ChevronRight, 
  LayoutDashboard, 
  ShieldAlert, 
  GitGraph, 
  FileCheck, 
  Bell, 
  Settings, 
  BrainCircuit, 
  Orbit, 
  Radar,
  X,
  Shield,
  ClipboardList,
} from 'lucide-react';

export default function Sidebar({ 
  activeTab, 
  setActiveTab, 
  collapsed, 
  setCollapsed,
  mobileOpen = false,
  setMobileOpen,
}) {
  const navItems = [
    { id: 'portal', label: 'Threat Radar', icon: Orbit, isPortal: true },
    { id: 'dashboard', label: 'Command Center', icon: LayoutDashboard },
    { id: 'inspector', label: 'Detection Studio', icon: ShieldAlert },
    { id: 'intelligence', label: 'Intelligence Operations', icon: BrainCircuit },
    { id: 'live', label: 'XDR Fusion', icon: Radar },
    { id: 'graph', label: 'Attack Graph', icon: GitGraph },
    { id: 'operations', label: 'Casework & Playbooks', icon: ClipboardList },
    { id: 'compliance', label: 'Compliance & Governance', icon: FileCheck },
    { id: 'notifications', label: 'Alert Inbox', icon: Bell },
    { id: 'admin', label: 'Administration', icon: Settings },
  ];

  const handleItemClick = (id) => {
    setActiveTab(id);
    if (setMobileOpen) {
      setMobileOpen(false);
    }
  };

  return (
    <>
      {/* Mobile Drawer Backdrop & Sheet */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex">
          {/* Dark Backdrop */}
          <div 
            onClick={() => setMobileOpen?.(false)}
            className="fixed inset-0 bg-black/75 backdrop-blur-sm transition-opacity animate-in fade-in duration-200"
            aria-hidden="true"
          />

          {/* Slide-out Mobile Navigation Drawer */}
          <aside className="relative w-72 max-w-[85vw] h-full bg-[#071524] border-r border-cyan-500/20 p-4 flex flex-col z-10 shadow-2xl overflow-y-auto">
            <div className="flex items-center justify-between pb-4 mb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  <Shield size={18} />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white tracking-wide">SOC Navigation</h3>
                  <p className="text-[10px] text-slate-400 font-mono">CyberGuard Suite</p>
                </div>
              </div>
              <button 
                type="button"
                onClick={() => setMobileOpen?.(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                title="Close Navigation"
              >
                <X size={18} />
              </button>
            </div>

            <nav className="space-y-1.5 flex-1 overflow-y-auto py-2">
              {navItems.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => handleItemClick(item.id)}
                    className={`nav-item w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition active:scale-[0.98] ${
                      isActive
                        ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-[0_0_12px_rgba(6,182,212,0.15)]'
                        : 'text-slate-300 hover:bg-slate-800/80 hover:text-white'
                    }`}
                  >
                    <Icon size={18} className="shrink-0" />
                    <span className="truncate">{item.label}</span>
                  </button>
                );
              })}
            </nav>

            <div className="pt-3 border-t border-slate-800/80 text-[11px] font-mono text-slate-400 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>SOC link secured 24/7</span>
            </div>
          </aside>
        </div>
      )}

      {/* Desktop / Large Screen Sidebar */}
      <aside className={`app-sidebar ${collapsed ? 'sidebar-collapsed' : ''} p-4 hidden md:flex md:flex-col transition-all duration-300`}>
        <div className="sidebar-top">
          <p className="sidebar-label">Operations</p>
          <button 
            type="button" 
            className="sidebar-toggle" 
            onClick={() => setCollapsed(!collapsed)} 
            title="Collapse navigation"
          >
            {collapsed ? <ChevronRight size={15} /> : <ChevronLeft size={15} />}
          </button>
        </div>
        <nav className="space-y-2 flex-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleItemClick(item.id)}
                className={`nav-item w-full flex items-center space-x-3 px-4 py-3 rounded-xl text-xs font-semibold transition ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                    : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                }`}
              >
                <Icon size={18} className="shrink-0" />
                {!collapsed && <span className="truncate">{item.label}</span>}
              </button>
            );
          })}
        </nav>
        {!collapsed && (
          <div className="sidebar-footer">
            <span className="live-pulse" /> SOC link secured <strong>24/7</strong>
          </div>
        )}
      </aside>
    </>
  );
}
