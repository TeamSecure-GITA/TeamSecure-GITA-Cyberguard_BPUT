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
import ThreatMap from './components/ThreatMap';
import IdentityRiskHeatmap from './components/IdentityRiskHeatmap';
import IocReputationFeed from './components/IocReputationFeed';
import TrustScanner from './components/TrustScanner';
import FrontierCapabilities from './components/FrontierCapabilities';
import AdvancedDefenseLab from './components/AdvancedDefenseLab';
import SpeculativeDefenseWidget from './components/SpeculativeDefenseWidget';
import SecurityFusionCenter from './components/SecurityFusionCenter';
import RoadmapCoveragePanel from './components/RoadmapCoveragePanel';
import { LanguageProvider } from './i18n';

export default function App() {
  const [viewMode, setViewMode] = useState('portal'); // 'portal' or 'workspace'
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
  const [demoSeeded, setDemoSeeded] = useState(false);
  const [routingInfo, setRoutingInfo] = useState(null);
  const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

  const handleQuickLogin = async (username, password) => {
    const response = await axios.post(`${apiBaseUrl}/api/v1/auth/login`, { username, password });
    if (!response.data.requires_otp) {
      setSession(response.data);
      setViewMode('workspace');
      setActiveTab('dashboard');
    }
    return response.data;
  };

  const handleVerifyOtp = async (challengeId, otp) => {
    const response = await axios.post(`${apiBaseUrl}/api/v1/auth/verify-otp`, { challenge_id: challengeId, otp });
    setSession(response.data);
    setViewMode('workspace');
    setActiveTab('dashboard');
    return response.data;
  };

  const handleVerifyPasskey = async (challengeId, credential) => {
    const response = await axios.post(`${apiBaseUrl}/api/v1/auth/passkey`, { challenge_id: challengeId, credential });
    setSession(response.data);
    setViewMode('workspace');
    setActiveTab('dashboard');
    return response.data;
  };

  React.useEffect(() => {
    if (!session) return;
    const config = { headers: { Authorization: `Bearer ${session.access_token}` } };
    const recoverUnauthorized = (result) => {
      if (result.status === 'rejected' && result.reason?.response?.status === 401) {
        setSession(null);
        setViewMode('portal');
        setRoutingInfo(null);
      }
    };
    Promise.allSettled([
      axios.get(`${apiBaseUrl}/api/v1/dashboard/metrics`, config),
      axios.get(`${apiBaseUrl}/api/v1/incidents`, config),
      axios.get(`${apiBaseUrl}/api/v1/dashboard/timeline`, config),
      axios.get(`${apiBaseUrl}/api/v1/system/health`, config),
      axios.get(`${apiBaseUrl}/api/v1/models/status`, config),
      axios.get(`${apiBaseUrl}/api/v1/notifications`, config),
    ]).then(([metricsResult, incidentsResult, timelineResult, healthResult, modelResult, notificationResult]) => {
      [metricsResult, incidentsResult, timelineResult, healthResult, modelResult, notificationResult].forEach(recoverUnauthorized);
      if (metricsResult.status === 'fulfilled') setMetrics(metricsResult.value.data);
      if (incidentsResult.status === 'fulfilled') setIncidents(incidentsResult.value.data.incidents || []);
      if (timelineResult.status === 'fulfilled') setTimeline(timelineResult.value.data || []);
      if (healthResult.status === 'fulfilled') setHealth(healthResult.value.data);
      if (modelResult.status === 'fulfilled') setModelStatus(modelResult.value.data);
      if (notificationResult.status === 'fulfilled') setUnread(notificationResult.value.data.unread || 0);
    });
    const timer = window.setInterval(() => setRefreshKey((value) => value + 1), 10000);
    return () => window.clearInterval(timer);
  }, [session, apiBaseUrl, refreshKey]);

  React.useEffect(() => {
    if (!session) {
      setRoutingInfo(null);
      return;
    }

    const config = { headers: { Authorization: `Bearer ${session.access_token}` } };
    axios.post(
      `${apiBaseUrl}/api/v1/alert-routing`,
      {
        incidents: incidents.length ? incidents : [],
        analysts: [{ username: session.user?.username || 'analyst', role: session.user?.role || 'analyst' }],
      },
      config,
    )
      .then((response) => setRoutingInfo(response.data))
      .catch((error) => {
        setRoutingInfo(null);
        if (error.response?.status === 401) {
          setSession(null);
          setViewMode('portal');
        }
      });
  }, [session, apiBaseUrl, incidents, refreshKey]);

  React.useEffect(() => {
    if (!session || demoSeeded || incidents.length > 0) return;

    const hydrateDemoData = async () => {
      try {
        const scenariosResponse = await axios.get(`${apiBaseUrl}/api/v1/demo/scenarios`, { headers: { Authorization: `Bearer ${session.access_token}` } });
        const scenarios = scenariosResponse.data.scenarios || [];
        if (!scenarios.length) {
          setDemoSeeded(true);
          return;
        }

        await Promise.allSettled(
          scenarios.map((scenario) => axios.post(
            `${apiBaseUrl}/api/v1/analyze`,
            { category: scenario.category, payload: scenario.payload },
            { headers: { Authorization: `Bearer ${session.access_token}` } },
          )),
        );

        setDemoSeeded(true);
        setRefreshKey((value) => value + 1);
      } catch {
        setDemoSeeded(true);
      }
    };

    hydrateDemoData();
  }, [session, incidents.length, demoSeeded, apiBaseUrl]);

  React.useEffect(() => {
    if (!session || typeof WebSocket === 'undefined') return undefined;
    const socketUrl = `${apiBaseUrl.replace(/^http/, 'ws')}/api/v1/ws/events?token=${encodeURIComponent(session.access_token)}`;
    let socket;
    try {
      socket = new WebSocket(socketUrl);
      socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          if (message.type !== 'heartbeat') setRefreshKey((value) => value + 1);
        } catch {
          setRefreshKey((value) => value + 1);
        }
      };
      socket.onopen = () => socket.send('subscribe');
    } catch {
      socket = undefined;
    }
    return () => socket?.close();
  }, [session, apiBaseUrl]);

  // Primary Landing View: Animated CyberGyroscopic Threat Radar Portal
  if (viewMode === 'portal') {
    return (
      <LanguageProvider language={language}>
        <CyberRadarPortal
          currentSession={session}
          currentLang={language}
          onLanguageChange={setLanguage}
          onOpenWorkspace={() => {
            if (!session) {
              handleQuickLogin('teamsecure.project@gmail.com', 'Secure@9040');
            } else {
              setViewMode('workspace');
              setActiveTab('dashboard');
            }
          }}
          onApprovedSession={(approvedSession) => {
            setSession(approvedSession);
            setViewMode('workspace');
            setActiveTab('dashboard');
          }}
          onQuickLogin={handleQuickLogin}
          onVerifyOtp={handleVerifyOtp}
          onVerifyPasskey={handleVerifyPasskey}
        />
      </LanguageProvider>
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
    <LanguageProvider language={language}>
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
                  <h2>CyberGuard AI<br /><span>Security Command Center</span></h2>
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
             <IncidentTable
               incidents={incidents}
               initialSearch={incidentSearch}
               accessToken={session?.access_token}
               routeData={routingInfo}
               onSelectIncident={setSelectedIncident}
               onRefresh={() => setRefreshKey((value) => value + 1)}
             />
            </>
          )}
{activeTab === 'graph' && <AttackGraph accessToken={session?.access_token} />}
{activeTab === 'inspector' && <ThreatInspector accessToken={session?.access_token} />}
{activeTab === 'compliance' && <ComplianceTab accessToken={session?.access_token} />}
{activeTab === 'notifications' && <NotificationsPanel accessToken={session?.access_token} workload={{ incidents, analysts: [{ username: session?.user?.username || 'analyst', role: session?.user?.role || 'analyst' }] }} />}
{activeTab === 'admin' && <AdminConsole accessToken={session?.access_token} routeData={routingInfo} />}
{activeTab === 'intelligence' && <ThreatIntelligence incidents={incidents} accessToken={session?.access_token} />}
{activeTab === 'live' && (
  <div className="space-y-5">
    <SecurityFusionCenter apiBaseUrl={apiBaseUrl} accessToken={session?.access_token} />
    <RoadmapCoveragePanel apiBaseUrl={apiBaseUrl} accessToken={session?.access_token} userRole={session?.user?.role} incidents={incidents} />
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
      <ThreatMap apiBaseUrl={apiBaseUrl} accessToken={session?.access_token} />
      <IdentityRiskHeatmap apiBaseUrl={apiBaseUrl} accessToken={session?.access_token} />
      <IocReputationFeed apiBaseUrl={apiBaseUrl} accessToken={session?.access_token} />
      <TrustScanner apiBaseUrl={apiBaseUrl} accessToken={session?.access_token} />
      <FrontierCapabilities apiBaseUrl={apiBaseUrl} accessToken={session?.access_token} />
      <AdvancedDefenseLab apiBaseUrl={apiBaseUrl} accessToken={session?.access_token} />
      <SpeculativeDefenseWidget apiBaseUrl={apiBaseUrl} accessToken={session?.access_token} />
    </div>
  </div>
)}
</main>
</div>

{selectedIncident && (
  <XaiModal
    incident={selectedIncident}
    onClose={() => setSelectedIncident(null)}
    userRole={session?.user?.role}
    accessToken={session?.access_token}
  />
)}
      </div>
    </LanguageProvider>
  );
}