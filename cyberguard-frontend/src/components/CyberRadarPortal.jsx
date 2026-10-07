import React, { useState } from 'react';
import { 
  Shield, 
  ArrowRight, 
  Lock, 
  LogIn,
  AlertTriangle,
  Play,
  Sun,
  Moon,
  Zap,
  Brain,
  ShieldCheck,
  Database,
  ChevronRight,
  Radio,
  FileCheck2,
  Mail,
  Activity,
  Eye,
  EyeOff,
  User,
} from 'lucide-react';
import LanguageToggle from './LanguageToggle';
import CyberGlobe from './CyberGlobe';
import WatchDemoModal from './WatchDemoModal';
import CyberVideoPlayerBar from './CyberVideoPlayerBar';
import { getApiBaseUrl } from '../apiConfig';
import { loginWithGoogle, formatFirebaseAuthError } from '../firebase';

const decodeBase64Url = (value) => {
  const padded = `${value}${'='.repeat((4 - (value.length % 4)) % 4)}`.replace(/-/g, '+').replace(/_/g, '/');
  const binary = window.atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

const preparePasskeyOptions = (options) => ({
  ...options,
  challenge: decodeBase64Url(options.challenge),
  user: options.user ? { ...options.user, id: decodeBase64Url(options.user.id) } : undefined,
  allowCredentials: options.allowCredentials?.map((item) => ({ ...item, id: decodeBase64Url(item.id) })),
  excludeCredentials: options.excludeCredentials?.map((item) => ({ ...item, id: decodeBase64Url(item.id) })),
});

const serializePasskey = (credential) => (typeof credential.toJSON === 'function' ? credential.toJSON() : {
  id: credential.id,
  rawId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  type: credential.type,
  response: {
    clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    ...(credential.response.attestationObject ? { attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.attestationObject))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') } : {}),
    ...(credential.response.authenticatorData ? { authenticatorData: btoa(String.fromCharCode(...new Uint8Array(credential.response.authenticatorData))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') } : {}),
    ...(credential.response.signature ? { signature: btoa(String.fromCharCode(...new Uint8Array(credential.response.signature))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') } : {}),
    ...(credential.response.userHandle ? { userHandle: btoa(String.fromCharCode(...new Uint8Array(credential.response.userHandle))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') } : {}),
  },
});

export default function CyberRadarPortal({
  onOpenWorkspace,
  onOpenLoginPage,
  onQuickLogin,
  onVerifyOtp,
  onVerifyPasskey,
  onApprovedSession,
  currentSession,
  currentLang,
  onLanguageChange,
  apiBaseUrl: propApiBaseUrl,
  themeMode: propThemeMode = 'dark',
  onThemeToggle,
}) {
  const apiBaseUrl = propApiBaseUrl || getApiBaseUrl();

  const [activeNav, setActiveNav] = useState('home');
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [showDemoModal, setShowDemoModal] = useState(false);
  const [showVideoBar, setShowVideoBar] = useState(true);
  const [themeMode, setThemeMode] = useState(propThemeMode || 'dark');

  React.useEffect(() => {
    if (propThemeMode) {
      setThemeMode(propThemeMode);
    }
  }, [propThemeMode]);

  const toggleTheme = (targetTheme) => {
    const next = targetTheme || (themeMode === 'dark' ? 'judge-white' : 'dark');
    setThemeMode(next);
    onThemeToggle?.(next);
  };

  const isLight = themeMode === 'judge-white' || themeMode === 'light';

  // Authentication states
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [authLoading, setAuthLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [authError, setAuthError] = useState(null);
  const [otpChallenge, setOtpChallenge] = useState(null);
  const [otp, setOtp] = useState('');
  const [requestEmail, setRequestEmail] = useState('');
  const [requestName, setRequestName] = useState('');
  const [requestPurpose, setRequestPurpose] = useState('');
  const [requestToken, setRequestToken] = useState('');
  const [requestState, setRequestState] = useState(null);
  const [requestLoading, setRequestLoading] = useState(false);
  const [authModalTab, setAuthModalTab] = useState('login');

  const handleGoogleLogin = async () => {
    setGoogleLoading(true);
    setAuthError(null);
    try {
      const session = await loginWithGoogle(apiBaseUrl);
      if (session) {
        if (onApprovedSession) {
          onApprovedSession(session);
        }
        setShowAuthModal(false);
      }
    } catch (err) {
      console.error('Google sign-in error:', err);
      setAuthError(formatFirebaseAuthError(err));
    } finally {
      setGoogleLoading(false);
    }
  };

  const handleLaunch = () => {
    if (currentSession) {
      onOpenWorkspace();
    } else {
      setShowAuthModal(true);
    }
  };

  const handleManualLogin = async (e) => {
    e.preventDefault();
    setAuthLoading(true);
    setAuthError(null);
    try {
      if (onQuickLogin) {
        const result = await onQuickLogin(loginUsername, loginPassword);
        if (result?.requires_passkey) {
          if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('This browser does not support passkeys.');
          const credential = result.kind === 'registration'
            ? await navigator.credentials.create({ publicKey: preparePasskeyOptions(result.options) })
            : await navigator.credentials.get({ publicKey: preparePasskeyOptions(result.options) });
          if (!credential) throw new Error('Passkey ceremony was cancelled.');
          await onVerifyPasskey(result.challenge_id, serializePasskey(credential));
          setShowAuthModal(false);
        } else {
          setShowAuthModal(false);
        }
      } else {
        throw new Error('The authentication service is unavailable.');
      }
    } catch (err) {
      if (!err.response) {
        setAuthError(err.message || `Backend unreachable or CORS blocked at ${apiBaseUrl}. Ensure the backend is running ('python main.py').`);
      } else if (err.response.status === 401) {
        setAuthError(err.response.data?.detail || 'Invalid username or password. Check credentials.');
      } else if (err.response.status === 403) {
        setAuthError(err.response.data?.detail || 'Access forbidden: Administrator authorization required.');
      } else if (err.response.status >= 500) {
        const detail = typeof err.response.data?.detail === 'string' ? err.response.data.detail : `Server error (HTTP ${err.response.status}).`;
        setAuthError(detail);
      } else {
        setAuthError(err.response.data?.detail || err.message || 'Authentication failed. Check credentials.');
      }
    } finally {
      setAuthLoading(false);
    }
  };

  const handleOtpVerification = async (event) => {
    event.preventDefault();
    setAuthLoading(true);
    setAuthError(null);
    try {
      await onVerifyOtp(otpChallenge.challenge_id, otp);
      setShowAuthModal(false);
      setOtpChallenge(null);
      setOtp('');
    } catch (err) {
      if (!err.response) {
        setAuthError(`Backend unreachable at ${apiBaseUrl}. Could not verify OTP.`);
      } else {
        setAuthError(err.response.data?.detail || err.message || 'OTP verification failed.');
      }
    } finally {
      setAuthLoading(false);
    }
  };

  const submitAccessRequest = async (event) => {
    event.preventDefault();
    setRequestLoading(true);
    setRequestState(null);
    setAuthError(null);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/access/request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: requestEmail, name: requestName, purpose: requestPurpose }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Unable to submit access request.');
      setRequestToken(data.request_token);
      setRequestState(data.email_sent ? 'Approval request sent to the security owner.' : 'Request saved in pending queue.');
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setRequestLoading(false);
    }
  };

  const checkAccessApproval = async () => {
    if (!requestToken) return;
    setRequestLoading(true);
    setAuthError(null);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/access/status?token=${encodeURIComponent(requestToken)}`);
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Unable to check approval status.');
      if (data.status === 'approved') {
        onApprovedSession(data);
        return;
      }
      setRequestState(`Request status: ${data.status}. Pending security owner approval.`);
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setRequestLoading(false);
    }
  };

  const toggleTheme = () => {
    setThemeMode((prev) => (prev === 'dark' ? 'high-contrast' : 'dark'));
  };

  const scrollToSection = (sectionId) => {
    setActiveNav(sectionId);
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className={`cyber-portal-root relative min-h-screen bg-[#020b18] text-slate-100 flex flex-col justify-between overflow-x-hidden ${themeMode === 'high-contrast' ? 'brightness-110 contrast-125' : ''}`}>
      {/* Background ambient lighting and cyber wave elements */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        {/* Subtle grid pattern */}
        <div className="cyber-matrix-grid absolute inset-0 opacity-[0.06]" />
        
        {/* Glowing cyan/teal ambient aura positioned around the right globe */}
        <div 
          className="absolute top-1/3 right-[8%] -translate-y-1/2 w-[700px] h-[700px] rounded-full blur-[160px] pointer-events-none"
          style={{
            background: 'radial-gradient(circle, rgba(6, 182, 212, 0.22) 0%, rgba(16, 185, 129, 0.18) 40%, rgba(14, 165, 233, 0.06) 70%, transparent 80%)'
          }}
        />

        {/* Ambient bottom left vignette */}
        <div 
          className="absolute -bottom-36 -left-36 w-[560px] h-[560px] rounded-full blur-[170px] pointer-events-none"
          style={{
            background: 'radial-gradient(circle, rgba(3, 105, 161, 0.18) 0%, transparent 75%)'
          }}
        />

        {/* Ambient top light streaks */}
        <div className="absolute top-0 inset-x-0 h-[1px] bg-gradient-to-r from-transparent via-cyan-500/30 to-transparent" />
      </div>

      {/* =========================================================================
          1. TOP NAVIGATION BAR (Exact visual layout matching reference screenshot)
          ========================================================================= */}
      <header className="relative z-30 w-full px-5 sm:px-10 py-4 flex items-center justify-between border-b border-cyan-500/10 backdrop-blur-md bg-[#020b18]/70">
        
        {/* Brand Logo: Shield with "C" + "CyberGuard AI" */}
        <div 
          onClick={() => scrollToSection('home')}
          className="flex items-center gap-3 cursor-pointer group select-none"
          title="CyberGuard AI Home"
        >
          {/* Glowing Cyber Shield Logo */}
          <div className="w-8 h-9 sm:w-9 sm:h-10 flex items-center justify-center shrink-0 transition-transform group-hover:scale-105 drop-shadow-[0_0_12px_rgba(6,182,212,0.8)]">
            <svg viewBox="0 0 100 120" className="w-full h-full overflow-visible" fill="none">
              <path
                d="M 50,6 C 64,6 84,11 93,20 C 93,56 82,92 50,116 C 18,92 7,56 7,20 C 16,11 36,6 50,6 Z"
                fill="url(#headerShieldBg)"
                stroke="#06b6d4"
                strokeWidth="5"
                strokeLinejoin="round"
              />
              <path
                d="M 50,14 C 61,14 77,18 84,25 C 84,54 75,84 50,105 C 25,84 16,54 16,25 C 23,18 39,14 50,14 Z"
                fill="none"
                stroke="#00e699"
                strokeWidth="2"
                strokeOpacity="0.6"
              />
              <text
                x="50"
                y="72"
                textAnchor="middle"
                fill="#00e699"
                fontSize="48"
                fontWeight="900"
                fontFamily="Space Grotesk, system-ui, sans-serif"
                style={{ filter: 'drop-shadow(0 0 8px rgba(0, 230, 153, 0.9))' }}
              >
                C
              </text>
              <defs>
                <radialGradient id="headerShieldBg" cx="50%" cy="30%" r="70%">
                  <stop offset="0%" stopColor="#042c3d" />
                  <stop offset="100%" stopColor="#010c17" />
                </radialGradient>
              </defs>
            </svg>
          </div>
          
          {/* Brand Typography */}
          <span className="text-lg sm:text-xl font-bold tracking-tight text-white flex items-center gap-1.5">
            CyberGuard <span className="font-bold text-cyan-400">AI</span>
          </span>
        </div>

        {/* Center Navigation Links: Home, Features, How It Works, About, Contact */}
        <nav className="hidden md:flex items-center gap-7 lg:gap-9 text-sm font-medium text-slate-300">
          <button
            onClick={() => scrollToSection('home')}
            className={`relative py-1 transition-colors cursor-pointer ${
              activeNav === 'home' ? 'text-white font-semibold' : 'text-slate-300 hover:text-white'
            }`}
          >
            <span>Home</span>
            {activeNav === 'home' && (
              <span className="absolute bottom-[-17px] inset-x-0 mx-auto w-7 h-[2.5px] rounded-full bg-cyan-400 shadow-[0_0_10px_#22d3ee]" />
            )}
          </button>

          <button
            onClick={() => scrollToSection('features')}
            className={`relative py-1 transition-colors cursor-pointer ${
              activeNav === 'features' ? 'text-white font-semibold' : 'text-slate-300 hover:text-white'
            }`}
          >
            <span>Features</span>
            {activeNav === 'features' && (
              <span className="absolute bottom-[-17px] inset-x-0 mx-auto w-7 h-[2.5px] rounded-full bg-cyan-400 shadow-[0_0_10px_#22d3ee]" />
            )}
          </button>

          <button
            onClick={() => scrollToSection('how-it-works')}
            className={`relative py-1 transition-colors cursor-pointer ${
              activeNav === 'how-it-works' ? 'text-white font-semibold' : 'text-slate-300 hover:text-white'
            }`}
          >
            <span>How It Works</span>
            {activeNav === 'how-it-works' && (
              <span className="absolute bottom-[-17px] inset-x-0 mx-auto w-7 h-[2.5px] rounded-full bg-cyan-400 shadow-[0_0_10px_#22d3ee]" />
            )}
          </button>

          <button
            onClick={() => scrollToSection('about')}
            className={`relative py-1 transition-colors cursor-pointer ${
              activeNav === 'about' ? 'text-white font-semibold' : 'text-slate-300 hover:text-white'
            }`}
          >
            <span>About</span>
            {activeNav === 'about' && (
              <span className="absolute bottom-[-17px] inset-x-0 mx-auto w-7 h-[2.5px] rounded-full bg-cyan-400 shadow-[0_0_10px_#22d3ee]" />
            )}
          </button>

          <button
            onClick={() => scrollToSection('contact')}
            className={`relative py-1 transition-colors cursor-pointer ${
              activeNav === 'contact' ? 'text-white font-semibold' : 'text-slate-300 hover:text-white'
            }`}
          >
            <span>Contact</span>
            {activeNav === 'contact' && (
              <span className="absolute bottom-[-17px] inset-x-0 mx-auto w-7 h-[2.5px] rounded-full bg-cyan-400 shadow-[0_0_10px_#22d3ee]" />
            )}
          </button>
        </nav>

        {/* Right Controls: [ 🌐 EN ⌵ ] [ ☀️ ] [ 🛡️ SOC Login ] */}
        <div className="flex items-center gap-2.5 sm:gap-3.5">
          {/* Language Selector Pill */}
          <LanguageToggle currentLang={currentLang} onToggle={onLanguageChange} variant="pill" />

          {/* Theme Mode Toggle Button */}
          <button
            type="button"
            onClick={toggleTheme}
            className="w-8 h-8 rounded-full border border-slate-700/80 bg-slate-900/60 hover:bg-slate-800/80 text-slate-300 hover:text-amber-300 flex items-center justify-center transition-all cursor-pointer shadow-sm"
            title="Toggle Visual Display Theme"
          >
            {themeMode === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
          </button>

          {/* SOC Login Pill Button */}
          <button
            type="button"
            id="header-soc-login-btn"
            onClick={() => setShowAuthModal(true)}
            className="flex items-center gap-1.5 sm:gap-2 px-3.5 sm:px-4 py-1.5 sm:py-2 rounded-full border border-cyan-500/50 bg-[#071d30]/70 hover:bg-cyan-950/60 text-xs sm:text-sm font-medium text-cyan-300 hover:text-white hover:border-cyan-400 transition-all shadow-[0_0_18px_rgba(6,182,212,0.2)] hover:shadow-[0_0_25px_rgba(6,182,212,0.4)] cursor-pointer shrink-0"
            title="SOC Operator Sign In"
          >
            <Shield size={14} className="text-cyan-400" />
            <span>{currentSession ? `SOC (${currentSession.user?.role || 'Lead'})` : 'SOC Login'}</span>
          </button>
        </div>
      </header>

      {/* =========================================================================
          2. MAIN SPLIT HERO SECTION (Exact visual layout matching reference screenshot)
          ========================================================================= */}
      <main id="home" className="relative z-20 flex-1 max-w-7xl w-full mx-auto px-6 sm:px-10 lg:px-12 pt-8 sm:pt-12 pb-16 flex flex-col lg:flex-row items-center justify-between gap-10 lg:gap-6">
        
        {/* Left Column: Hero Typography & CTAs */}
        <div className="flex-1 max-w-xl flex flex-col items-start text-left z-20 space-y-6">
          
          {/* Eyebrow Pill Tag: [ ● THREAT INTELLIGENCE  ● REAL-TIME  ● AI POWERED ] */}
          <div className="inline-flex items-center gap-2 sm:gap-3 px-3.5 py-1.5 rounded-full border border-emerald-500/30 bg-[#041a23]/80 backdrop-blur-md shadow-[0_0_18px_rgba(16,185,129,0.15)] font-mono text-[10px] sm:text-[11px] font-semibold tracking-wider text-emerald-400">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399]" />
              THREAT INTELLIGENCE
            </span>
            <span className="text-emerald-500/40">●</span>
            <span className="flex items-center gap-1.5">
              REAL-TIME
            </span>
            <span className="text-emerald-500/40">●</span>
            <span className="flex items-center gap-1.5">
              AI POWERED
            </span>
          </div>

          {/* Main Hero Headline */}
          <h1
            aria-label="See the signal before it spreads."
            className="text-4xl sm:text-5xl lg:text-[62px] font-black tracking-tight text-white leading-[1.08]"
          >
            See the signal <br />
            <span className="text-[#00e699] font-black drop-shadow-[0_0_35px_rgba(0,230,153,0.55)]">
              before it spreads.
            </span>
          </h1>

          {/* Subtitle Description */}
          <p className="text-base sm:text-lg text-slate-300/90 leading-relaxed font-normal max-w-lg">
            CyberGuard AI turns suspicious links, messages, senders, and synthetic media clues into a clear risk picture and structured next moves.
          </p>

          {/* Action Buttons: [ Open detection workspace ➔ ]  [ ▷ Watch demo ] */}
          <div className="pt-2 flex flex-col sm:flex-row items-stretch sm:items-center gap-3.5 sm:gap-4 w-full sm:w-auto">
            
            {/* Primary CTA: Open detection workspace */}
            <button
              id="hero-open-workspace-btn"
              onClick={handleLaunch}
              className="group relative inline-flex items-center justify-center gap-2.5 px-6 sm:px-8 py-3.5 sm:py-4 rounded-xl font-bold text-[#011e17] text-sm sm:text-base transition-all duration-300 shadow-[0_0_35px_rgba(0,230,153,0.5)] hover:shadow-[0_0_50px_rgba(0,245,255,0.7)] hover:scale-[1.02] active:scale-[0.98] cursor-pointer"
              style={{
                background: 'linear-gradient(135deg, #00e699 0%, #00d2a8 50%, #06b6d4 100%)',
              }}
            >
              <Shield size={17} className="text-[#021815] shrink-0" />
              <span className="tracking-wide">
                Open detection workspace
              </span>
              <ArrowRight 
                size={18} 
                className="text-[#021815] transition-transform duration-300 group-hover:translate-x-1.5 shrink-0" 
              />
              <span className="absolute inset-0 rounded-xl bg-white/20 opacity-0 group-hover:opacity-100 transition-opacity" />
            </button>

            {/* Secondary CTA: Watch demo */}
            <button
              type="button"
              id="hero-watch-demo-btn"
              onClick={() => setShowDemoModal(true)}
              className="inline-flex items-center justify-center gap-2.5 px-5 sm:px-6 py-3.5 sm:py-4 rounded-xl font-medium text-white text-sm sm:text-base border border-slate-700/80 bg-slate-900/60 hover:bg-slate-800/80 hover:border-cyan-500/50 backdrop-blur-md shadow-md transition-all duration-200 hover:scale-[1.02] active:scale-[0.98] cursor-pointer"
            >
              <div className="w-5 h-5 rounded-full border border-white/60 flex items-center justify-center pl-0.5">
                <Play size={10} className="fill-white text-white" />
              </div>
              <span>Watch demo</span>
            </button>

          </div>

          {/* Privacy Footnote Badge: [ 🔒 Privacy by design | Local-first analysis with restricted telemetry fallback. ] */}
          <div className="pt-3 flex items-start gap-2.5 max-w-md">
            <div className="p-1 rounded-md bg-emerald-500/10 text-emerald-400 mt-0.5 shrink-0">
              <Lock size={15} />
            </div>
            <div className="flex flex-col text-xs leading-snug">
              <span className="font-semibold text-slate-200">Privacy by design</span>
              <span className="text-slate-400 text-[11px]">
                Local-first analysis with restricted telemetry fallback.
              </span>
            </div>
          </div>

        </div>

        {/* Right Column: 3D Holographic Cyber Earth Globe & Orbiting Telemetry Badges */}
        <div className="flex-1 w-full max-w-full lg:max-w-[580px] flex items-center justify-center relative">
          <CyberGlobe 
            onOpenWorkspace={handleLaunch} 
            onSelectBadge={(badgeId) => {
              if (badgeId === 'url' || badgeId === 'ip') handleLaunch();
              else setShowDemoModal(true);
            }} 
          />
        </div>

      </main>

      {/* =========================================================================
          3. BOTTOM FEATURE CARDS DOCK (Exact 4 columns matching reference screenshot)
          ========================================================================= */}
      <section className="relative z-20 w-full border-t border-cyan-500/15 bg-[#030d1d]/85 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-6 sm:px-10 py-6 sm:py-8">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 lg:gap-8">
            
            {/* Card 1: Real-time Detection */}
            <div className="flex items-start gap-4 group">
              <div className="w-12 h-12 rounded-2xl bg-cyan-950/70 border border-cyan-500/40 text-cyan-400 flex items-center justify-center shrink-0 shadow-[0_0_20px_rgba(6,182,212,0.3)] group-hover:scale-105 group-hover:border-cyan-300 transition-all">
                <Zap size={22} className="text-cyan-400" />
              </div>
              <div className="flex flex-col">
                <h4 className="text-sm font-bold text-white group-hover:text-cyan-300 transition-colors">
                  Real-time Detection
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed mt-1">
                  Identify threats as they emerge across multiple channels.
                </p>
              </div>
            </div>

            {/* Card 2: AI-Powered Analysis */}
            <div className="flex items-start gap-4 group">
              <div className="w-12 h-12 rounded-2xl bg-blue-950/70 border border-blue-500/40 text-blue-400 flex items-center justify-center shrink-0 shadow-[0_0_20px_rgba(59,130,246,0.3)] group-hover:scale-105 group-hover:border-blue-300 transition-all">
                <Brain size={22} className="text-blue-400" />
              </div>
              <div className="flex flex-col">
                <h4 className="text-sm font-bold text-white group-hover:text-blue-300 transition-colors">
                  AI-Powered Analysis
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed mt-1">
                  Leverage machine learning and behavioral intelligence.
                </p>
              </div>
            </div>

            {/* Card 3: Actionable Insights */}
            <div className="flex items-start gap-4 group">
              <div className="w-12 h-12 rounded-2xl bg-purple-950/70 border border-purple-500/40 text-purple-400 flex items-center justify-center shrink-0 shadow-[0_0_20px_rgba(168,85,247,0.3)] group-hover:scale-105 group-hover:border-purple-300 transition-all">
                <ShieldCheck size={22} className="text-purple-400" />
              </div>
              <div className="flex flex-col">
                <h4 className="text-sm font-bold text-white group-hover:text-purple-300 transition-colors">
                  Actionable Insights
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed mt-1">
                  Get clear risk scores and next-step recommendations.
                </p>
              </div>
            </div>

            {/* Card 4: Secure & Private */}
            <div className="flex items-start gap-4 group">
              <div className="w-12 h-12 rounded-2xl bg-emerald-950/70 border border-emerald-500/40 text-emerald-400 flex items-center justify-center shrink-0 shadow-[0_0_20px_rgba(16,185,129,0.3)] group-hover:scale-105 group-hover:border-emerald-300 transition-all">
                <Database size={22} className="text-emerald-400" />
              </div>
              <div className="flex flex-col">
                <h4 className="text-sm font-bold text-white group-hover:text-emerald-300 transition-colors">
                  Secure & Private
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed mt-1">
                  Your data stays yours, with local-first processing.
                </p>
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* =========================================================================
          4. EXTENDED SHOWCASE SECTIONS (Features, How It Works, About, Contact)
          ========================================================================= */}
      
      {/* Features Section */}
      <section id="features" className="relative z-20 py-16 px-6 sm:px-10 border-t border-slate-800/80 bg-[#020914]">
        <div className="max-w-7xl mx-auto space-y-10">
          <div className="text-center max-w-2xl mx-auto space-y-3">
            <span className="text-xs font-mono font-bold text-cyan-400 tracking-widest uppercase">
              // ARCHITECTURE CAPABILITIES
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white">
              End-to-End Autonomous Defense Shield
            </h2>
            <p className="text-sm sm:text-base text-slate-400">
              CyberGuard AI inspects suspicious signals across university domains, student portals, executive communications, and network edge gateways.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-6 rounded-2xl bg-[#051424] border border-cyan-500/20 hover:border-cyan-500/50 transition-all space-y-4 shadow-lg group">
              <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center group-hover:scale-105 transition-transform">
                <Radio size={24} />
              </div>
              <h3 className="text-lg font-bold text-white">Neural Phishing Triangulation</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Extracts typosquatting distance, zero-day domain age, SSL telemetry, and malicious DOM exfiltration patterns in sub-50ms.
              </p>
              <div className="pt-2 font-mono text-[11px] text-cyan-300 flex items-center gap-1.5">
                <span>99.4% F1 Detection Benchmark</span>
              </div>
            </div>

            <div className="p-6 rounded-2xl bg-[#051424] border border-emerald-500/20 hover:border-emerald-500/50 transition-all space-y-4 shadow-lg group">
              <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center group-hover:scale-105 transition-transform">
                <Activity size={24} />
              </div>
              <h3 className="text-lg font-bold text-white">Deepfake & Synthetic Media Forensics</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Spectral analysis scans voice recordings and video frames for diffusion-model artifacts, acoustic jitter anomalies, and facial boundary mismatch.
              </p>
              <div className="pt-2 font-mono text-[11px] text-emerald-300 flex items-center gap-1.5">
                <span>Voice & Face Liveness Verification</span>
              </div>
            </div>

            <div className="p-6 rounded-2xl bg-[#051424] border border-indigo-500/20 hover:border-indigo-500/50 transition-all space-y-4 shadow-lg group">
              <div className="w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 flex items-center justify-center group-hover:scale-105 transition-transform">
                <FileCheck2 size={24} />
              </div>
              <h3 className="text-lg font-bold text-white">XAI Explainability & Automated Containment</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Generates plain-language forensic justifications and directly triggers Cloudflare WAF firewall rules and account isolation.
              </p>
              <div className="pt-2 font-mono text-[11px] text-indigo-300 flex items-center gap-1.5">
                <span>Direct WAF / LDAP Orchestration</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="how-it-works" className="relative z-20 py-16 px-6 sm:px-10 border-t border-slate-800/80 bg-[#030d1d]">
        <div className="max-w-7xl mx-auto space-y-12">
          <div className="text-center max-w-2xl mx-auto space-y-3">
            <span className="text-xs font-mono font-bold text-emerald-400 tracking-widest uppercase">
              // OPERATING PIPELINE
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white">
              How CyberGuard AI Secures BPUT Digital Assets
            </h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="p-5 rounded-2xl bg-[#051322] border border-slate-800 space-y-3">
              <span className="text-2xl font-black font-mono text-cyan-400">01</span>
              <h4 className="text-base font-bold text-white">Signal Ingestion</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Telemetry streams into the SOC from DNS resolvers, campus mail gateways, edge WAF proxies, and endpoint sensors.
              </p>
            </div>

            <div className="p-5 rounded-2xl bg-[#051322] border border-slate-800 space-y-3">
              <span className="text-2xl font-black font-mono text-emerald-400">02</span>
              <h4 className="text-base font-bold text-white">Multi-Engine AI Triage</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Parallel inference classifies threat vectors across phishing, audio deepfake clones, and malicious Tor ingress.
              </p>
            </div>

            <div className="p-5 rounded-2xl bg-[#051322] border border-slate-800 space-y-3">
              <span className="text-2xl font-black font-mono text-indigo-400">03</span>
              <h4 className="text-base font-bold text-white">XAI Evidence Scoring</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Explainable AI maps concrete feature weights and risk confidence factors for immediate SOC analyst inspection.
              </p>
            </div>

            <div className="p-5 rounded-2xl bg-[#051322] border border-slate-800 space-y-3">
              <span className="text-2xl font-black font-mono text-amber-400">04</span>
              <h4 className="text-base font-bold text-white">Containment & Rescue</h4>
              <p className="text-xs text-slate-400 leading-relaxed">
                Dynamic containment actions quarantine compromised credentials, block malicious IPs, and dispatch automated alerts.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* About & Contact Section */}
      <section id="about" className="relative z-20 py-16 px-6 sm:px-10 border-t border-slate-800/80 bg-[#020b18]">
        <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
          
          <div className="space-y-4">
            <span className="text-xs font-mono font-bold text-cyan-400 tracking-widest uppercase">
              // ABOUT BPUT INNOVATION SUBMISSION
            </span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white">
              Pioneered for BPUT Cyber Resilience
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed">
              CyberGuard AI was developed by TeamSecure to provide an autonomous, privacy-preserving defense perimeter for BPUT students, faculty, and state university infrastructure against emerging AI-generated cyber warfare.
            </p>
            <div className="flex flex-wrap gap-3 pt-2">
              <span className="px-3 py-1 rounded-full bg-cyan-950/40 border border-cyan-500/30 text-xs font-mono text-cyan-300">
                TeamSecure-GITA
              </span>
              <span className="px-3 py-1 rounded-full bg-emerald-950/40 border border-emerald-500/30 text-xs font-mono text-emerald-300">
                ODISHA CYBER DEFENSE INITIATIVE
              </span>
            </div>
          </div>

          <div id="contact" className="p-6 sm:p-8 rounded-2xl bg-[#061525] border border-slate-700/80 space-y-5">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <Mail size={18} className="text-cyan-400" />
              <span>SOC Operations & Contact</span>
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Have an urgent security incident to report or need authorization credentials for the BPUT SOC operations room?
            </p>
            <div className="space-y-3 text-xs font-mono text-slate-300">
              <div className="flex items-center gap-2.5 p-3 rounded-xl bg-[#030d19] border border-slate-800">
                <Mail size={15} className="text-cyan-400 shrink-0" />
                <span>teamsecure.project@gmail.com</span>
              </div>
              <div className="flex items-center gap-2.5 p-3 rounded-xl bg-[#030d19] border border-slate-800">
                <Shield size={15} className="text-emerald-400 shrink-0" />
                <span>BPUT Incident Response Desk: 24/7 Monitored</span>
              </div>
            </div>
            <button
              onClick={() => setShowAuthModal(true)}
              className="w-full py-3 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-bold text-xs sm:text-sm transition-all shadow-md cursor-pointer"
            >
              Sign In to SOC Operations
            </button>
          </div>

        </div>
      </section>

      {/* Footer System Status Bar */}
      <footer className="relative z-20 w-full px-5 sm:px-10 py-4 border-t border-slate-800/80 bg-[#010712] backdrop-blur-md flex flex-col sm:flex-row flex-wrap items-center justify-between text-[11px] sm:text-xs font-mono text-slate-400 gap-2 sm:gap-4 text-center sm:text-left">
        <div className="flex items-center justify-center sm:justify-start gap-3 sm:gap-6 flex-wrap">
          <span className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            BPUT CYBER DEFENSE INITIATIVE
          </span>
          <span className="hidden sm:inline text-slate-700">|</span>
          <span className="text-slate-500">
            LOCAL & DISTRIBUTED HYBRID SENSORS (v2.4)
          </span>
        </div>

        <div className="flex items-center justify-center sm:justify-end gap-3 sm:gap-5 flex-wrap">
          <span className="text-slate-500">Authenticated access required</span>
          <button 
            onClick={handleLaunch} 
            className="text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 transition-colors cursor-pointer"
          >
            <span>Open Command View</span>
            <ChevronRight size={13} />
          </button>
        </div>
      </footer>

      {/* =========================================================================
          5. WATCH DEMO MODAL (Interactive live threat analysis walkthrough)
          ========================================================================= */}
      <WatchDemoModal
        isOpen={showDemoModal}
        onClose={() => setShowDemoModal(false)}
        onLaunchWorkspace={handleLaunch}
      />

      {/* =========================================================================
          6. SOC AUTHENTICATION MODAL (Enhanced with Google SSO & Presets)
          ========================================================================= */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/80 backdrop-blur-md overflow-y-auto">
          <div className="relative w-full max-w-[390px] sm:max-w-[420px] max-h-[94dvh] overflow-y-auto p-5 sm:p-6 rounded-2xl bg-[#081726]/95 backdrop-blur-xl border border-cyan-500/30 shadow-[0_0_50px_rgba(6,182,212,0.25)] space-y-4 my-auto animate-in fade-in zoom-in-95 duration-150">
            
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="p-1.5 sm:p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shrink-0">
                  <Shield size={18} className="text-cyan-400" />
                </div>
                <div>
                  <h3 className="text-sm sm:text-base font-bold text-white flex items-center gap-2">
                    SOC Authentication
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-mono border border-emerald-500/30 bg-emerald-950/40 text-emerald-400 font-semibold">
                      v2.4
                    </span>
                  </h3>
                  <p className="text-[10px] sm:text-xs text-slate-400">CyberGuard Operations Access</p>
                </div>
              </div>
              <button 
                onClick={() => setShowAuthModal(false)}
                className="text-slate-400 hover:text-white text-base font-mono p-1 rounded-lg hover:bg-slate-800/60 transition-colors cursor-pointer"
                title="Close"
              >
                ✕
              </button>
            </div>

            {authModalTab === 'login' ? (
              <div className="space-y-3.5">
                {!otpChallenge ? (
                  <div className="space-y-3">
                    {/* Google One-Click Login Button */}
                    <button
                      type="button"
                      onClick={handleGoogleLogin}
                      disabled={googleLoading || authLoading}
                      className="w-full py-2.5 px-4 rounded-xl bg-white hover:bg-slate-100 active:bg-slate-200 text-slate-900 font-semibold text-xs sm:text-sm shadow-[0_2px_12px_rgba(255,255,255,0.15)] hover:shadow-[0_4px_20px_rgba(255,255,255,0.25)] transition-all flex items-center justify-center gap-2.5 cursor-pointer disabled:opacity-50 border border-slate-200"
                    >
                      {googleLoading ? (
                        <>
                          <span className="w-4 h-4 border-2 border-slate-900 border-t-transparent rounded-full animate-spin shrink-0" />
                          <span>Connecting with Google...</span>
                        </>
                      ) : (
                        <>
                          <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" />
                            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" />
                          </svg>
                          <span>Continue with Google</span>
                        </>
                      )}
                    </button>

                    {/* Cyber styled Divider */}
                    <div className="relative flex items-center justify-center my-1">
                      <div className="border-t border-slate-700/60 w-full" />
                      <span className="bg-[#081726] px-2.5 text-[10px] font-mono text-slate-400 uppercase tracking-widest shrink-0">
                        or credentials
                      </span>
                      <div className="border-t border-slate-700/60 w-full" />
                    </div>

                    {/* Credentials Form */}
                    <form onSubmit={handleManualLogin} className="space-y-2.5">
                      <div>
                        <label className="block text-[10px] sm:text-[11px] font-mono text-slate-300 mb-1 flex items-center justify-between">
                          <span>USERNAME OR EMAIL</span>
                        </label>
                        <div className="relative">
                          <input
                            type="text"
                            value={loginUsername}
                            onChange={(e) => setLoginUsername(e.target.value)}
                            placeholder="username or email"
                            className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-[#040c17] border border-slate-700 text-white font-mono text-xs focus:border-cyan-500 focus:outline-none transition-colors"
                            required
                          />
                          <User size={13} className="absolute left-2.5 top-2 text-slate-500" />
                        </div>
                      </div>

                      <div>
                        <label className="block text-[10px] sm:text-[11px] font-mono text-slate-300 mb-1">PASSWORD</label>
                        <div className="relative">
                          <input
                            type={showPassword ? 'text' : 'password'}
                            value={loginPassword}
                            onChange={(e) => setLoginPassword(e.target.value)}
                            placeholder="Enter password or select demo role above"
                            className="w-full pl-8 pr-8 py-1.5 rounded-lg bg-[#040c17] border border-slate-700 text-white font-mono text-xs focus:border-cyan-500 focus:outline-none transition-colors"
                            required
                          />
                          <Lock size={13} className="absolute left-2.5 top-2 text-slate-500" />
                          <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            className="absolute right-2 top-1.5 text-slate-400 hover:text-white transition-colors cursor-pointer p-0.5"
                            title={showPassword ? 'Hide password' : 'Show password'}
                          >
                            {showPassword ? <EyeOff size={13} /> : <Eye size={13} />}
                          </button>
                        </div>
                      </div>

                      {authError && (
                        <div className="p-2 rounded-lg bg-rose-950/40 border border-rose-500/30 text-[11px] text-rose-300 font-mono space-y-1 animate-in fade-in">
                          <div className="flex items-start gap-1.5">
                            <AlertTriangle size={14} className="text-rose-400 mt-0.5 shrink-0" />
                            <span className="leading-snug">{authError}</span>
                          </div>
                        </div>
                      )}

                      <button
                        type="submit"
                        disabled={authLoading}
                        className="w-full py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 via-cyan-500 to-blue-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-bold text-xs sm:text-sm shadow-[0_0_20px_rgba(16,185,129,0.25)] hover:shadow-[0_0_25px_rgba(6,182,212,0.4)] transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
                      >
                        {authLoading ? (
                          <>
                            <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                            <span>Verifying...</span>
                          </>
                        ) : (
                          <>
                            <LogIn size={14} />
                            <span>Authenticate</span>
                          </>
                        )}
                      </button>

                      {/* Helper to switch to dedicated login page or request access */}
                      <div className="flex items-center justify-between pt-1 border-t border-slate-800/60 text-[10px] font-mono">
                        {onOpenLoginPage && (
                          <button
                            type="button"
                            onClick={() => {
                              setShowAuthModal(false);
                              onOpenLoginPage();
                            }}
                            className="text-slate-400 hover:text-cyan-300 underline"
                          >
                            Dedicated Page →
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => setAuthModalTab('request')}
                          className="text-cyan-400 hover:text-cyan-300 underline ml-auto"
                        >
                          Request Access
                        </button>
                      </div>
                    </form>
                  </div>
                ) : (
                  <form onSubmit={handleOtpVerification} className="space-y-3">
                    <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-200">
                      A one-time password was sent to {otpChallenge.masked_email}.
                    </div>
                    <label className="block text-xs font-mono text-slate-300">
                      ONE-TIME PASSWORD
                      <input
                        required
                        inputMode="numeric"
                        pattern="[0-9]{6}"
                        maxLength={6}
                        value={otp}
                        onChange={(event) => setOtp(event.target.value.replace(/\D/g, ''))}
                        className="mt-1.5 w-full px-3 py-2 rounded-lg bg-[#040c17] border border-slate-700 text-white font-mono text-sm tracking-[0.4em] focus:border-cyan-500 focus:outline-none"
                        placeholder="000000"
                      />
                    </label>
                    <button
                      type="submit"
                      disabled={authLoading || otp.length !== 6}
                      className="w-full py-2 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 text-slate-950 font-bold text-xs disabled:opacity-50"
                    >
                      {authLoading ? 'Verifying OTP...' : 'Verify and enter workspace'}
                    </button>
                  </form>
                )}
              </div>
            ) : (
              /* Request Temporary Access View */
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-white">Request Temporary Access</span>
                  <button
                    type="button"
                    onClick={() => setAuthModalTab('login')}
                    className="text-[10px] font-mono text-cyan-400 hover:underline"
                  >
                    ← Back to Sign In
                  </button>
                </div>
                <p className="text-[10px] text-slate-400 leading-snug">
                  Submit your details for SOC administrator approval.
                </p>
                <form onSubmit={submitAccessRequest} className="space-y-2">
                  <input
                    required
                    type="email"
                    value={requestEmail}
                    onChange={(event) => setRequestEmail(event.target.value)}
                    placeholder="Your official email address"
                    className="w-full px-2.5 py-1.5 rounded-lg bg-[#040c17] border border-slate-700 text-white text-xs focus:border-cyan-500 focus:outline-none font-mono"
                  />
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      type="text"
                      value={requestName}
                      onChange={(event) => setRequestName(event.target.value)}
                      placeholder="Name"
                      className="w-full px-2.5 py-1.5 rounded-lg bg-[#040c17] border border-slate-700 text-white text-xs focus:border-cyan-500 focus:outline-none"
                    />
                    <input
                      type="text"
                      value={requestPurpose}
                      onChange={(event) => setRequestPurpose(event.target.value)}
                      placeholder="Purpose"
                      className="w-full px-2.5 py-1.5 rounded-lg bg-[#040c17] border border-slate-700 text-white text-xs focus:border-cyan-500 focus:outline-none"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={requestLoading}
                    className="w-full py-1.5 rounded-lg border border-amber-400/40 text-amber-300 hover:bg-amber-400/10 disabled:opacity-50 text-xs font-semibold transition-colors"
                  >
                    {requestLoading ? 'Submitting...' : 'Submit Access Request'}
                  </button>
                </form>
                {requestState && <p className="text-[11px] text-emerald-300 font-mono">{requestState}</p>}
                {requestToken && (
                  <button
                    type="button"
                    onClick={checkAccessApproval}
                    disabled={requestLoading}
                    className="w-full py-1.5 rounded-lg border border-cyan-400/40 text-cyan-300 hover:bg-cyan-400/10 disabled:opacity-50 text-xs font-semibold transition-colors"
                  >
                    Check approval status
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
