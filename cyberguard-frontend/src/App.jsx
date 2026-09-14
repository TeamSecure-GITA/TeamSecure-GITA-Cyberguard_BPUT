import React, { useState } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import MetricCards from './components/MetricCards';
import ThreatChart from './components/ThreatChart';
import IncidentTable from './components/IncidentTable';
import ThreatInspector from './components/ThreatInspector';
import XaiModal from './components/XaiModal';
import AttackGraph from './components/AttackGraph';
import SystemHealth from './components/SystemHealth';
import ComplianceTab from './components/ComplianceTab';
import LanguageToggle from './components/LanguageToggle';
import CyberRadarPortal from './components/CyberRadarPortal';
import axios from 'axios';
import NotificationsPanel from './components/NotificationsPanel';
import AdminConsole from './components/AdminConsole';
import ThreatCards from './components/ThreatCards';
import SystemView from './components/SystemView';
import RiskGauge from './components/RiskGauge';
import ThreatFeed from './components/ThreatFeed';
import ThreatIntelligence from './components/ThreatIntelligence';

export default function App() {
  const [viewMode, setViewMode] = useState('workspace'); // 'workspace' or 'portal'
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [language, setLanguage] = useState('EN');
  const [session, setSession] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [health, setHealth] = useState(null);
  const [modelStatus, setModelStatus] = useState(null);
  const [unread, setUnread] = useState(0);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [incidentSearch, setIncidentSearch] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);
  const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

  const handleQuickLogin = async (username = 'lead', password = 'lead123') => {
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/auth/login`, { username, password });
      setSession(response.data);
      return response.data;
    } catch (err) {
      const fallbackSession = {
        access_token: 'offline-demo-token',
        token_type: 'bearer',
        user: { username, role: username === 'lead' ? 'lead' : 'analyst' }
      };
      setSession(fallbackSession);
      return fallbackSession;
    }
  };

  React.useEffect(() => {
    if (!session) {
      handleQuickLogin('lead', 'lead123');
    }
  }, []);

  React.useEffect(() => {
    if (!session) return;
    const config = { headers: { Authorization: `Bearer ${session.access_token}` } };
    Promise.all([
      axios.get(`${apiBaseUrl}/api/v1/dashboard/metrics`, config),
      axios.get(`${apiBaseUrl}/api/v1/incidents`, config),
      axios.get(`${apiBaseUrl}/api/v1/dashboard/timeline`, config),
      axios.get(`${apiBaseUrl}/api/v1/system/health`, config),
      axios.get(`${apiBaseUrl}/api/v1/models/status`, config),
      axios.get(`${apiBaseUrl}/api/v1/notifications`, config),
    ]).then(([metricsResponse, incidentsResponse, timelineResponse, healthResponse, modelResponse, notificationResponse]) => {
      setMetrics(metricsResponse.data);
      setIncidents(incidentsResponse.data.incidents || []);
      setTimeline(timelineResponse.data || []);
      setHealth(healthResponse.data);
      setModelStatus(modelResponse.data);
      setUnread(notificationResponse.data.unread || 0);
    }).catch(() => {
      setMetrics(null);
      setIncidents([]);
    });
    const timer = window.setInterval(() => setRefreshKey((value) => value + 1), 10000);
    return () => window.clearInterval(timer);
  }, [session, apiBaseUrl, refreshKey]);

  // Primary Landing View: Animated CyberGyroscopic Threat Radar Portal
  if (viewMode === 'portal') {
    return (
      <CyberRadarPortal
        currentSession={session}
        onOpenWorkspace={() => {
          if (!session) {
            handleQuickLogin('lead', 'lead123');
          } else {
            setViewMode('workspace');
            setActiveTab('dashboard');
          }
        }}
        onQuickLogin={handleQuickLogin}
      />
    );
  }

  const handleSidebarTabChange = (tabId) => {
    if (tabId === 'portal') {
      setViewMode('portal');
    } else {
      setActiveTab(tabId);
    }
  };

  return (
    <div className="app-shell min-h-screen text-slate-100 flex flex-col bg-[#05111f]">
      <div className="utility-bar">
        <span><span className="utility-dot" />BPUT SOC / INNOVATION SUBMISSION</span>
        <LanguageToggle currentLang={language} onToggle={setLanguage} />
      </div>

      <Header 
        userRole={session?.user?.role || 'lead'} 
        unread={unread} 
        onSearch={(query) => { setIncidentSearch(query); setActiveTab('dashboard'); }} 
        onOpenNotifications={() => setActiveTab('notifications')}
        onReturnToPortal={() => setViewMode('portal')}
        onLogout={() => { setSession(null); setViewMode('portal'); }}
      />

      <div className="flex flex-1">
        <Sidebar 
          activeTab={activeTab} 
          setActiveTab={handleSidebarTabChange} 
          collapsed={sidebarCollapsed} 
          setCollapsed={setSidebarCollapsed} 
        />
        
        <main className="workspace flex-1 p-6 overflow-y-auto space-y-6">
          <SystemHealth health={health} />

          {activeTab === 'dashboard' && (
            <>
              <section className="command-hero">
                <div className="hero-grid" />
                <div>
                  <div className="hero-kicker"><span className="live-pulse" /> AI SECURITY OPERATIONS CENTER</div>
                  <h2>CyberGuard AI<br /><span>Command Center</span></h2>
                  <p>One operating picture for detection, explanation, and response across BPUT digital assets.</p>
                </div>
                <div className="hero-status"><span className="hero-status-label">Posture</span><strong>{health?.status === 'healthy' ? 'Operational' : 'Checking'}</strong><span>Updated live from the AI engine</span></div>
              </section>
              <MetricCards metrics={metrics} />
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                <div className="xl:col-span-2"><ThreatCards metrics={metrics} /></div>
                <RiskGauge metrics={metrics} />
              </div>
              <SystemView health={health} modelStatus={modelStatus} />
              <div className="grid grid-cols-1 xl:grid-cols-[1.45fr_.85fr] gap-4">
                <ThreatChart timeline={timeline} />
                <ThreatFeed incidents={incidents} onSelectIncident={setSelectedIncident} />
              </div>
              <IncidentTable incidents={incidents} initialSearch={incidentSearch} accessToken={session.access_token} onRefresh={() => setRefreshKey((value) => value + 1)} onSelectIncident={(inc) => setSelectedIncident(inc)} />
            </>
          )}

          {activeTab === 'graph' && <AttackGraph accessToken={session.access_token} />}
          {activeTab === 'inspector' && <ThreatInspector accessToken={session.access_token} />}
          {activeTab === 'compliance' && <ComplianceTab accessToken={session.access_token} />}
          {activeTab === 'notifications' && <NotificationsPanel accessToken={session.access_token} />}
          {activeTab === 'admin' && <AdminConsole accessToken={session.access_token} />}
          {activeTab === 'intelligence' && <ThreatIntelligence accessToken={session.access_token} incidents={incidents} />}
        </main>
      </div>

      <XaiModal
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
        userRole={session.user.role}
        accessToken={session.access_token}
      />
    </div>
  );
}