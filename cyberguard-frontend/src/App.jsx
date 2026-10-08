import React, { useEffect, useState } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import LanguageToggle from './components/LanguageToggle';
import { getApiBaseUrl } from './apiConfig';
import axios from 'axios';
const MetricCards = React.lazy(() => import('./components/MetricCards'));
const MostTargeted = React.lazy(() => import('./components/MostTargeted'));
const ThreatChart = React.lazy(() => import('./components/ThreatChart'));
const IncidentTable = React.lazy(() => import('./components/IncidentTable'));
const ThreatInspector = React.lazy(() => import('./components/ThreatInspector'));
const OperationsWorkspace = React.lazy(() => import('./components/OperationsWorkspace'));
const XaiModal = React.lazy(() => import('./components/XaiModal'));
const SystemHealth = React.lazy(() => import('./components/SystemHealth'));
const ComplianceTab = React.lazy(() => import('./components/ComplianceTab'));
const CyberRadarPortal = React.lazy(() => import('./components/CyberRadarPortal'));
const NotificationsPanel = React.lazy(() => import('./components/NotificationsPanel'));
const AdminConsole = React.lazy(() => import('./components/AdminConsole'));
const ThreatCards = React.lazy(() => import('./components/ThreatCards'));
const SystemView = React.lazy(() => import('./components/SystemView'));
const RiskGauge = React.lazy(() => import('./components/RiskGauge'));
const ThreatFeed = React.lazy(() => import('./components/ThreatFeed'));
const ThreatIntelligence = React.lazy(() => import('./components/ThreatIntelligence'));
const ThreatMap = React.lazy(() => import('./components/ThreatMap'));
const IdentityRiskHeatmap = React.lazy(() => import('./components/IdentityRiskHeatmap'));
const IocReputationFeed = React.lazy(() => import('./components/IocReputationFeed'));
const TrustScanner = React.lazy(() => import('./components/TrustScanner'));
const FrontierCapabilities = React.lazy(() => import('./components/FrontierCapabilities'));
const AdvancedDefenseLab = React.lazy(() => import('./components/AdvancedDefenseLab'));
const SpeculativeDefenseWidget = React.lazy(() => import('./components/SpeculativeDefenseWidget'));
const SecurityFusionCenter = React.lazy(() => import('./components/SecurityFusionCenter'));
const RoadmapCoveragePanel = React.lazy(() => import('./components/RoadmapCoveragePanel'));
const PreventionCenter = React.lazy(() => import('./components/PreventionCenter'));
const CampaignWatchlist = React.lazy(() => import('./components/CampaignWatchlist'));
const IdentityTrustPanel = React.lazy(() => import('./components/IdentityTrustPanel'));
const DeceptionPanel = React.lazy(() => import('./components/DeceptionPanel'));
const InsiderRiskPanel = React.lazy(() => import('./components/InsiderRiskPanel'));
const ContainmentQueue = React.lazy(() => import('./components/ContainmentQueue'));
const PolicyEnginePanel = React.lazy(() => import('./components/PolicyEnginePanel'));
const AccountRescueCenter = React.lazy(() => import('./components/AccountRescueCenter'));
const Login = React.lazy(() => import('./components/Login'));
import { LanguageProvider } from './i18n';
import { formatFirebaseAuthError } from './firebaseErrors';

const AttackGraph = React.lazy(() => import('./components/AttackGraph'));

export default function App() {
  const getInitialViewMode = () => {
    if (typeof window !== 'undefined') {
      const path = window.location.pathname.toLowerCase();
      const hash = window.location.hash.toLowerCase();
      const search = window.location.search.toLowerCase();
      if (path === '/login' || hash === '#login' || search.includes('login') || search.includes('view=login')) {
        return 'login';
      }
    }
    return 'portal';
  };
  const [viewMode, setViewMode] = useState(getInitialViewMode); // 'portal', 'login', or 'workspace'
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [language, setLanguage] = useState(() => {
    if (typeof window === 'undefined') return 'EN';
    const savedLanguage = window.localStorage.getItem('cyberguard_language');
    return ['EN', 'OD', 'HI'].includes(savedLanguage) ? savedLanguage : 'EN';
  });
  const [session, setSession] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [health, setHealth] = useState(null);
  const [modelStatus, setModelStatus] = useState(null);
  const [unread, setUnread] = useState(0);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [incidentSearch, setIncidentSearch] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);
  const [demoSeeded, setDemoSeeded] = useState(false);
  const [routingInfo, setRoutingInfo] = useState(null);
  const [googleRedirectError, setGoogleRedirectError] = useState(null);

  useEffect(() => {
    window.localStorage.setItem('cyberguard_language', language);
  }, [language]);
  const [themeMode, setThemeMode] = useState(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('cyberguard_theme');
      if (saved) return saved;
      if (window.location.search.includes('mode=judge') || window.location.search.includes('theme=white')) return 'judge-white';
    }
    return 'dark';
  });

  const handleThemeToggle = (newTheme) => {
    const next = typeof newTheme === 'string' ? newTheme : (themeMode === 'dark' ? 'judge-white' : 'dark');
    setThemeMode(next);
    if (typeof window !== 'undefined') {
      localStorage.setItem('cyberguard_theme', next);
      document.documentElement.setAttribute('data-theme', next);
    }
  };

  React.useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', themeMode);
    }
  }, [themeMode]);

  const authFailureHandled = React.useRef(false);
  const apiBaseUrl = getApiBaseUrl();

  React.useEffect(() => {
    const redirectParams = new URLSearchParams(window.location.search);
    if (redirectParams.get('authType') !== 'signInViaRedirect') return undefined;
    let active = true;
    import('./firebase')
      .then(({ completeGoogleRedirect }) => completeGoogleRedirect(apiBaseUrl))
      .then((approvedSession) => {
        if (!active || !approvedSession) return;
        authFailureHandled.current = false;
        setSession(approvedSession);
        setViewMode('workspace');
        setActiveTab('dashboard');
      })
      .catch((error) => {
        console.error('Google redirect sign-in error:', error);
        if (active) {
          setGoogleRedirectError(formatFirebaseAuthError(error));
          setViewMode('login');
        }
      });
    return () => {
      active = false;
    };
  }, [apiBaseUrl]);

  const sessionRef = React.useRef(session);
  React.useEffect(() => {
    sessionRef.current = session;
  }, [session]);

  React.useEffect(() => {
    const interceptorId = axios.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          window.dispatchEvent(new Event('cyberguard:auth-expired'));
        }
        return Promise.reject(error);
      },
    );
    const handleAuthExpired = () => {
      if (authFailureHandled.current) return;
      authFailureHandled.current = true;
      setSession(null);
      setViewMode('portal');
      setRoutingInfo(null);
      setMetrics(null);
      setIncidents([]);
      setTimeline([]);
      setHealth(null);
      setModelStatus(null);
      setUnread(0);
      setDemoSeeded(false);
    };
    window.addEventListener('cyberguard:auth-expired', handleAuthExpired);
    return () => {
      axios.interceptors.response.eject(interceptorId);
      window.removeEventListener('cyberguard:auth-expired', handleAuthExpired);
    };
  }, []);

  const handleQuickLogin = async (username, password) => {
    const response = await axios.post(
      `${apiBaseUrl}/api/v1/auth/login`,
      { username, password },
      { timeout: 90000 },
    );
    if (!response.data.requires_otp) {
      authFailureHandled.current = false;
      setSession(response.data);
      setViewMode('workspace');
      setActiveTab('dashboard');
    }
    return response.data;
  };

  const handleVerifyOtp = async (challengeId, otp) => {
    const response = await axios.post(`${apiBaseUrl}/api/v1/auth/verify-otp`, { challenge_id: challengeId, otp });
    authFailureHandled.current = false;
    setSession(response.data);
    setViewMode('workspace');
    setActiveTab('dashboard');
    return response.data;
  };

  const handleVerifyPasskey = async (challengeId, credential) => {
    const response = await axios.post(`${apiBaseUrl}/api/v1/auth/passkey`, { challenge_id: challengeId, credential });
    authFailureHandled.current = false;
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
    if (!session) return;

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

        const incidentsResponse = await axios.get(`${apiBaseUrl}/api/v1/incidents`, {
          headers: { Authorization: `Bearer ${session.access_token}` },
        });
        setIncidents(incidentsResponse.data.incidents || []);
        setDemoSeeded(true);
        setRefreshKey((value) => value + 1);
      } catch {
        setDemoSeeded(true);
      }
    };

    hydrateDemoData();
  }, [session, incidents.length, demoSeeded, apiBaseUrl]);

  React.useEffect(() => {
    if (!session?.access_token || typeof WebSocket === 'undefined') return undefined;
    const socketUrl = `${apiBaseUrl.replace(/^http/, 'ws')}/api/v1/ws/events`;
    let socket;
    try {
      socket = new WebSocket(socketUrl, [session.access_token, 'cyberguard.events.v1']);
      socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          if (message.type !== 'heartbeat') setRefreshKey((value) => value + 1);
        } catch {
          setRefreshKey((value) => value + 1);
        }
      };
    } catch {
      socket = undefined;
    }
    return () => socket?.close();
  }, [session, apiBaseUrl]);

  React.useEffect(() => {
    const handleNavigation = () => {
      const path = window.location.pathname.toLowerCase();
      const hash = window.location.hash.toLowerCase();
      const search = window.location.search.toLowerCase();
      if (path === '/login' || hash === '#login' || search.includes('login') || search.includes('view=login')) {
        setViewMode('login');
      } else if (hash === '#portal' || (path === '/' && hash === '')) {
        if (!session) setViewMode('portal');
      }
    };
    window.addEventListener('popstate', handleNavigation);
    window.addEventListener('hashchange', handleNavigation);
    return () => {
      window.removeEventListener('popstate', handleNavigation);
      window.removeEventListener('hashchange', handleNavigation);
    };
  }, [session]);

  // Dedicated Login View
  if (viewMode === 'login') {
    return (
      <LanguageProvider language={language}>
        <React.Suspense fallback={<p role="status">Loading authentication…</p>}>
          <Login
            googleAuthError={googleRedirectError}
            onLogin={(approvedSession) => {
              authFailureHandled.current = false;
              setSession(approvedSession);
              setViewMode('workspace');
              setActiveTab('dashboard');
            }}
            onReturnToPortal={() => {
              if (window.location.hash === '#login') {
                window.history.pushState(null, '', window.location.pathname);
              }
              setViewMode('portal');
            }}
          />
        </React.Suspense>
      </LanguageProvider>
    );
  }

  // Primary Landing View: Animated CyberGyroscopic Threat Radar Portal
  if (viewMode === 'portal') {
    return (
      <LanguageProvider language={language}>
        <React.Suspense fallback={<p role="status">Loading CyberGuard…</p>}>
          <CyberRadarPortal
            apiBaseUrl={apiBaseUrl}
            currentSession={session}
            currentLang={language}
            onLanguageChange={setLanguage}
            onOpenLoginPage={() => setViewMode('login')}
            onOpenWorkspace={() => {
              if (session) {
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
            themeMode={themeMode}
            onThemeToggle={handleThemeToggle}
          />
        </React.Suspense>
      </LanguageProvider>
    );
  }

  const handleSidebarTabChange = (tabId) => {
    if (tabId === 'portal') {
      setViewMode('portal');
    } else {
      setActiveTab(tabId);
    }
    setMobileMenuOpen(false);
  };

  return (
    <LanguageProvider language={language}>
      <div className="app-shell min-h-screen min-h-[100dvh] text-slate-100 flex flex-col bg-[#05111f] overflow-x-hidden">
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
        mobileMenuOpen={mobileMenuOpen}
        setMobileMenuOpen={setMobileMenuOpen}
        themeMode={themeMode}
        onToggleTheme={handleThemeToggle}
      />

      <div className="workspace-shell flex flex-1 relative overflow-x-hidden">
        <Sidebar 
          activeTab={activeTab} 
          setActiveTab={handleSidebarTabChange} 
          collapsed={sidebarCollapsed} 
          setCollapsed={setSidebarCollapsed} 
          mobileOpen={mobileMenuOpen}
          setMobileOpen={setMobileMenuOpen}
        />
        
        <main className={`workspace flex-1 p-3 sm:p-4 md:p-6 overflow-y-auto space-y-4 sm:space-y-6 max-w-full ${sidebarCollapsed ? 'workspace-sidebar-collapsed' : 'workspace-sidebar-expanded'}`}>
          <React.Suspense fallback={<p role="status">Loading workspace…</p>}>
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
              <MostTargeted targets={metrics?.topTargets} />
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                <div className="xl:col-span-2"><ThreatCards metrics={metrics} /></div>
                <RiskGauge metrics={metrics} />
              </div>
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                <PreventionCenter accessToken={session?.access_token} />
                <CampaignWatchlist accessToken={session?.access_token} />
              </div>
              <AccountRescueCenter accessToken={session?.access_token} />
              <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                <IdentityTrustPanel accessToken={session?.access_token} />
                <DeceptionPanel accessToken={session?.access_token} />
                <InsiderRiskPanel accessToken={session?.access_token} />
              </div>
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                <ContainmentQueue accessToken={session?.access_token} userRole={session?.user?.role} />
                <PolicyEnginePanel accessToken={session?.access_token} userRole={session?.user?.role} />
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
{activeTab === 'graph' && (
  <React.Suspense fallback={<p role="status">Loading attack graph…</p>}>
    <AttackGraph accessToken={session?.access_token} />
  </React.Suspense>
)}
{activeTab === 'operations' && <OperationsWorkspace accessToken={session?.access_token} incidents={incidents} />}
{activeTab === 'inspector' && (
  <ThreatInspector
    accessToken={session?.access_token}
    onIncidentCreated={() => setRefreshKey((value) => value + 1)}
  />
)}
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
          </React.Suspense>
</main>
</div>

{selectedIncident && (
  <React.Suspense fallback={<p role="status">Loading incident explanation…</p>}>
    <XaiModal
      incident={selectedIncident}
      onClose={() => setSelectedIncident(null)}
      userRole={session?.user?.role}
      accessToken={session?.access_token}
    />
  </React.Suspense>
)}
      </div>
    </LanguageProvider>
  );
}
