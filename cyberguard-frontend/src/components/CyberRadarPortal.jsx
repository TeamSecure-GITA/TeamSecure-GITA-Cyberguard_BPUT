import React, { useState } from 'react';
import { 
  Shield, 
  ArrowRight, 
  Lock, 
  AlertTriangle,
  ChevronRight,
} from 'lucide-react';
import LanguageToggle from './LanguageToggle';
import { getApiBaseUrl, setApiBaseUrl } from '../apiConfig';
import { loginWithGoogle } from '../firebase';

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
  onQuickLogin,
  onVerifyOtp,
  onVerifyPasskey,
  onApprovedSession,
  currentSession,
  currentLang,
  onLanguageChange,
  apiBaseUrl: propApiBaseUrl,
}) {
  const apiBaseUrl = propApiBaseUrl || getApiBaseUrl();
  const [serverEndpointInput, setServerEndpointInput] = useState(apiBaseUrl);
  const [showServerConfig, setShowServerConfig] = useState(false);

  const [showAuthModal, setShowAuthModal] = useState(false);
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState(null);
  const [otpChallenge, setOtpChallenge] = useState(null);
  const [otp, setOtp] = useState('');
  const [requestEmail, setRequestEmail] = useState('');
  const [requestName, setRequestName] = useState('');
  const [requestPurpose, setRequestPurpose] = useState('');
  const [requestToken, setRequestToken] = useState('');
  const [requestState, setRequestState] = useState(null);
  const [requestLoading, setRequestLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [authModalTab, setAuthModalTab] = useState('login');

  const handleGoogleSignIn = async () => {
    setGoogleLoading(true);
    setAuthError(null);
    try {
      const session = await loginWithGoogle(apiBaseUrl);
      if (session) {
        if (onApprovedSession) {
          onApprovedSession(session);
        } else if (onOpenWorkspace) {
          onOpenWorkspace();
        }
        setShowAuthModal(false);
      }
    } catch (err) {
      console.error('Google sign-in error:', err);
      if (err.code === 'auth/popup-closed-by-user') {
        setAuthError('Google sign-in was cancelled.');
      } else if (err.code === 'auth/popup-blocked') {
        setAuthError('Popup blocked by browser. Please enable popups or tap Continue with Google again.');
      } else {
        setAuthError(err.message || 'Google authentication failed.');
      }
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
        onOpenWorkspace();
      }
    } catch (err) {
      if (!err.response) {
        setAuthError(`Backend unreachable at ${apiBaseUrl}. Ensure the backend service is deployed and active.`);
      } else if (err.response.status === 401) {
        setAuthError(err.response.data?.detail || 'Invalid username or password. Check credentials.');
      } else if (err.response.status === 403) {
        setAuthError(err.response.data?.detail || 'Access forbidden: Administrator authorization required.');
      } else if (err.response.status === 502 || err.response.status === 503 || err.response.status === 504) {
        setAuthError(`Backend is temporarily unavailable (HTTP ${err.response.status}). If deployed on Render free tier, the instance may be spinning up from idle (please wait ~30s and retry).`);
      } else if (err.response.status >= 500) {
        const detail = typeof err.response.data?.detail === 'string' ? err.response.data.detail : `Server error (HTTP ${err.response.status}). Check backend logs.`;
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
      setRequestState(data.email_sent ? 'Approval request sent to the security owner.' : 'Request saved, but SMTP is not configured yet.');
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
      setRequestState(`Request status: ${data.status}. The security owner must approve access first.`);
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setRequestLoading(false);
    }
  };

  return (
    <div className="cyber-portal-root relative min-h-screen bg-[#040c17] text-slate-100 flex flex-col justify-between overflow-x-hidden select-none">
      {/* Background ambient lighting and cyber grid */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        {/* Subtle cyber grid */}
        <div className="cyber-matrix-grid absolute inset-0 opacity-[0.07]" />
        
        {/* Glowing cyan/emerald ambient aura behind right radar orb */}
        <div 
          className="absolute top-1/2 right-[12%] -translate-y-1/2 w-[650px] h-[650px] rounded-full blur-[140px] pointer-events-none"
          style={{
            background: 'radial-gradient(circle, rgba(16, 185, 129, 0.28) 0%, rgba(6, 182, 212, 0.22) 38%, rgba(14, 165, 233, 0.08) 65%, transparent 80%)'
          }}
        />

        {/* Ambient bottom left vignette */}
        <div 
          className="absolute -bottom-32 -left-32 w-[500px] h-[500px] rounded-full blur-[150px] pointer-events-none"
          style={{
            background: 'radial-gradient(circle, rgba(3, 105, 161, 0.2) 0%, transparent 75%)'
          }}
        />
      </div>

      {/* Top Navigation Bar */}
      <header className="relative z-20 w-full px-4 sm:px-8 py-3.5 sm:py-5 flex items-center justify-between border-b border-cyan-500/10 backdrop-blur-md bg-[#040c17]/60">
        {/* Brand Logo */}
        <div className="flex items-center gap-2.5 sm:gap-3">
          <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-xl bg-gradient-to-br from-emerald-400/20 via-cyan-500/20 to-transparent border border-emerald-400/40 p-0.5 shadow-[0_0_20px_rgba(16,185,129,0.3)] flex items-center justify-center shrink-0">
            <div className="w-full h-full rounded-[10px] bg-[#061826] flex items-center justify-center">
              <span className="font-mono font-black text-emerald-400 text-base sm:text-xl tracking-tighter shadow-sm">C</span>
            </div>
          </div>
          <div className="flex flex-col">
            <span className="text-base sm:text-xl font-bold tracking-tight text-white flex items-center gap-1.5">
              CyberGuard <span className="text-emerald-400 font-semibold">AI</span>
            </span>
          </div>
        </div>

        {/* Workspace status and controls */}
        <div className="flex items-center gap-2 sm:gap-4">
          <LanguageToggle currentLang={currentLang} onToggle={onLanguageChange} />
          <div className="inline-flex items-center gap-1.5 sm:gap-2 px-2.5 sm:px-3 py-1 sm:py-1.5 rounded-full border border-emerald-500/30 bg-emerald-950/30 text-emerald-400 font-mono text-[10px] sm:text-[11px] tracking-wider shadow-[0_0_15px_rgba(16,185,129,0.15)] shrink-0">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="font-semibold">[ CYBERGUARD WORKSPACE READY ]</span>
          </div>

          <button
            onClick={() => setShowAuthModal(true)}
            aria-label={currentSession ? `Signed in: ${currentSession.user?.username || 'SOC Lead'}` : 'SOC Login'}
            className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg border border-slate-700/80 bg-slate-800/40 text-xs font-mono text-slate-300 hover:text-cyan-300 hover:border-cyan-500/40 transition-all shrink-0"
            title="Authentication & Access"
          >
            <Lock size={12} className="text-cyan-400" />
            <span className="hidden sm:inline">{currentSession ? `Signed in: ${currentSession.user?.username || 'SOC Lead'}` : 'SOC Login'}</span>
            <span className="sm:hidden">{currentSession ? 'Signed' : 'Login'}</span>
          </button>
        </div>
      </header>

      {/* Main Split Hero Viewport */}
      <main className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-6 md:px-12 py-8 flex flex-col lg:flex-row items-center justify-between gap-12 lg:gap-8">
        
        {/* Left Column: Hero Content */}
        <div className="flex-1 max-w-xl flex flex-col items-start text-left z-10 space-y-6">
          
          {/* Eyebrow Kicker */}
          <div className="inline-flex items-center gap-2 text-cyan-400 font-mono text-[11px] font-semibold tracking-[0.22em] uppercase">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            THREAT INTELLIGENCE, MADE ACTIONABLE
          </div>

          {/* Hero Headline */}
          <h1 className="text-4xl sm:text-5xl lg:text-[62px] font-extrabold tracking-tight text-white leading-[1.08]">
            See the signal{' '}
            <br />
            <span className="bg-gradient-to-r from-amber-400 via-orange-400 to-amber-500 bg-clip-text text-transparent drop-shadow-[0_0_35px_rgba(245,158,11,0.35)]">
              before it spreads.
            </span>
          </h1>

          {/* Subtitle Description */}
          <p className="text-base sm:text-lg text-slate-300/85 leading-relaxed font-normal max-w-lg">
            CyberGuard AI turns suspicious links, messages, senders, and synthetic media clues into a clear risk picture and structured next moves.
          </p>

          {/* CTA Action Button */}
          {/* CTA Action Buttons */}
          <div className="pt-2 flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center gap-3 sm:gap-4 w-full">
            <button
              id="open-detection-workspace-btn"
              onClick={handleLaunch}
              className="group relative inline-flex items-center justify-center gap-3 px-6 sm:px-8 py-3.5 sm:py-4 rounded-xl font-medium text-slate-950 font-semibold text-sm sm:text-base transition-all duration-300 shadow-[0_0_30px_rgba(16,185,129,0.45)] hover:shadow-[0_0_45px_rgba(6,182,212,0.65)] hover:scale-[1.02] active:scale-[0.98]"
              style={{
                background: 'linear-gradient(135deg, #34d399 0%, #10b981 40%, #06b6d4 100%)',
              }}
            >
              <span className="relative z-10 tracking-wide font-bold text-[#041d1a]">
                Open detection workspace
              </span>
              <ArrowRight 
                size={18} 
                className="relative z-10 text-[#041d1a] transition-transform duration-300 group-hover:translate-x-1.5 shrink-0" 
              />
              {/* Button neon sheen */}
              <span className="absolute inset-0 rounded-xl bg-white/20 opacity-0 group-hover:opacity-100 transition-opacity" />
            </button>

            {/* Quick Google Sign In */}
            {!currentSession && (
              <button
                type="button"
                onClick={handleGoogleSignIn}
                disabled={googleLoading}
                className="inline-flex items-center justify-center gap-2.5 px-4 sm:px-5 py-3 sm:py-3.5 rounded-xl font-medium text-white text-xs sm:text-sm bg-slate-900/90 hover:bg-slate-800/90 border border-slate-700/80 hover:border-cyan-500/50 shadow-md transition-all duration-200 active:scale-[0.98] disabled:opacity-50"
              >
                <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
                </svg>
                <span>{googleLoading ? 'Signing in...' : 'Sign in with Google'}</span>
              </button>
            )}

            {currentSession && (
              <span className="text-xs font-mono text-emerald-400/90 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-emerald-950/40 border border-emerald-500/20">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                Session Active ({currentSession.user?.role?.toUpperCase()})
              </span>
            )}
          </div>

          {/* Trust & Privacy Badge */}
          <div className="pt-4 flex items-start gap-3 border-t border-slate-800/80 w-full max-w-md">
            <div className="p-1.5 rounded-md bg-emerald-500/10 text-emerald-400 mt-0.5 border border-emerald-500/20">
              <Shield size={16} />
            </div>
            <div className="flex flex-col text-xs">
              <span className="font-semibold text-slate-200">Privacy by design</span>
              <span className="text-slate-400 text-[11px] leading-relaxed">
                Local-first analysis with restricted telemetry fallback.
              </span>
            </div>
          </div>
        </div>

        {/* Right Column: Animated Cyber Gyroscope / Radar Sphere HUD */}
        <div className="flex-1 w-full max-w-full lg:max-w-[560px] flex items-center justify-center relative min-h-[340px] sm:min-h-[460px] py-4 overflow-hidden">
          
          {/* Main Gyroscope Container */}
          <div className="relative w-[280px] h-[280px] xs:w-[320px] xs:h-[320px] sm:w-[420px] sm:h-[420px] md:w-[440px] md:h-[440px] flex items-center justify-center">
            
            {/* Outer Static HUD Range Rings */}
            <div className="absolute inset-0 rounded-full border border-cyan-500/15" />
            <div className="absolute inset-6 sm:inset-8 rounded-full border border-emerald-500/20 border-dashed animate-[spin_120s_linear_infinite]" />
            <div className="absolute inset-14 sm:inset-20 rounded-full border border-cyan-400/25" />

            {/* Crosshair grid lines */}
            <div className="absolute w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-500/20 to-transparent pointer-events-none" />
            <div className="absolute h-full w-[1px] bg-gradient-to-b from-transparent via-cyan-500/20 to-transparent pointer-events-none" />

            {/* Radar Sweeper Line (Conic gradient rotation) */}
            <div 
              className="absolute inset-3 sm:inset-4 rounded-full pointer-events-none animate-[radar-sweep_5s_linear_infinite]"
              style={{
                background: 'conic-gradient(from 0deg, rgba(16, 185, 129, 0.28) 0deg, rgba(6, 182, 212, 0.08) 45deg, transparent 90deg, transparent 360deg)'
              }}
            />

            {/* 3D Gyroscope Orbital Ring 1: Tilted Positive Axis */}
            <div 
              className="gyro-orbit-ring gyro-ring-1 absolute w-[260px] h-[130px] xs:w-[300px] xs:h-[150px] sm:w-[400px] sm:h-[200px] rounded-[50%] border-2 border-emerald-400/40 pointer-events-none"
              style={{
                boxShadow: '0 0 20px rgba(16, 185, 129, 0.2), inset 0 0 15px rgba(16, 185, 129, 0.1)',
                transform: 'rotateX(68deg) rotateY(18deg) rotateZ(0deg)',
              }}
            >
              {/* Photon node orbiting on ring 1 */}
              <div className="gyro-photon-node photon-1" />
            </div>

            {/* 3D Gyroscope Orbital Ring 2: Tilted Negative Axis */}
            <div 
              className="gyro-orbit-ring gyro-ring-2 absolute w-[250px] h-[125px] xs:w-[280px] xs:h-[140px] sm:w-[380px] sm:h-[190px] rounded-[50%] border-2 border-cyan-400/45 pointer-events-none"
              style={{
                boxShadow: '0 0 25px rgba(6, 182, 212, 0.25), inset 0 0 20px rgba(6, 182, 212, 0.15)',
                transform: 'rotateX(68deg) rotateY(-28deg) rotateZ(45deg)',
              }}
            >
              {/* Photon node orbiting on ring 2 */}
              <div className="gyro-photon-node photon-2" />
            </div>

            {/* 3D Gyroscope Orbital Ring 3: Vertical-inclined Axis */}
            <div 
              className="gyro-orbit-ring gyro-ring-3 absolute w-[220px] h-[110px] xs:w-[250px] xs:h-[125px] sm:w-[340px] sm:h-[170px] rounded-[50%] border border-teal-300/35 pointer-events-none"
              style={{
                boxShadow: '0 0 15px rgba(45, 212, 191, 0.2)',
                transform: 'rotateX(74deg) rotateY(42deg) rotateZ(-30deg)',
              }}
            />

            {/* Central Holographic Core Badge */}
            <div 
              onClick={handleLaunch}
              className="group cursor-pointer relative z-20 w-28 h-28 xs:w-32 xs:h-32 sm:w-36 sm:h-36 rounded-full flex flex-col items-center justify-center backdrop-blur-xl transition-all duration-300 hover:scale-105 active:scale-95"
              style={{
                background: 'radial-gradient(circle, rgba(16, 185, 129, 0.32) 0%, rgba(6, 24, 38, 0.88) 75%, rgba(4, 12, 23, 0.95) 100%)',
                border: '2px solid rgba(52, 211, 153, 0.65)',
                boxShadow: '0 0 45px rgba(16, 185, 129, 0.5), inset 0 0 30px rgba(16, 185, 129, 0.35)',
              }}
            >
              {/* Inner Pulsing Radar Glow */}
              <div className="absolute inset-2 rounded-full border border-emerald-400/40 animate-ping opacity-25 pointer-events-none" />
              
              {/* Monogram Glyph */}
              <span className="text-2xl xs:text-3xl sm:text-4xl font-extrabold tracking-wider text-white drop-shadow-[0_0_15px_rgba(255,255,255,0.8)]">
                CG
              </span>
              
              <div className="mt-0.5 sm:mt-1 flex items-center gap-1 text-[9px] sm:text-[10px] font-mono text-emerald-300 tracking-wider">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                <span>CYBERGUARD</span>
              </div>
            </div>

            {/* Floating Cyber HUD Telemetry Tags with Tracer Lines */}

            {/* Tag 1: [ URL / WEB ] (Top-Left) */}
            <div className="hud-badge top-left absolute top-0 left-0 sm:-top-4 sm:left-4 z-20 flex items-center gap-1.5 sm:gap-2 px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-md bg-[#071929]/90 border border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.2)]">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              <span className="font-mono text-[9px] sm:text-[10px] text-cyan-200 font-semibold tracking-wider">
                URL / WEB
              </span>
              <div className="hidden sm:block absolute right-[-24px] bottom-[-14px] w-6 h-[1px] bg-cyan-500/40 rotate-[35deg]" />
            </div>

            {/* Tag 2: [ IP / SCAN ] (Top-Right) */}
            <div className="hud-badge top-right absolute top-2 right-0 sm:top-4 sm:-right-4 z-20 flex items-center gap-1.5 sm:gap-2 px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-md bg-[#071929]/90 border border-emerald-500/40 shadow-[0_0_12px_rgba(16,185,129,0.2)]">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="font-mono text-[9px] sm:text-[10px] text-emerald-200 font-semibold tracking-wider">
                IP / SCAN
              </span>
              <div className="hidden sm:block absolute left-[-24px] bottom-[-14px] w-6 h-[1px] bg-emerald-500/40 -rotate-[35deg]" />
            </div>

            {/* Tag 3: [ TOR / RELAY ] (Bottom-Right) */}
            <div className="hud-badge bottom-right absolute bottom-6 right-0 sm:bottom-14 sm:-right-6 z-20 flex items-center gap-1.5 sm:gap-2 px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-md bg-[#071929]/90 border border-amber-500/40 shadow-[0_0_12px_rgba(245,158,11,0.2)]">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
              <span className="font-mono text-[9px] sm:text-[10px] text-amber-200 font-semibold tracking-wider">
                TOR / RELAY
              </span>
              <div className="hidden sm:block absolute left-[-22px] top-[-10px] w-6 h-[1px] bg-amber-500/40 rotate-[30deg]" />
            </div>

            {/* Tag 4: [ DEEPFAKE / AUDIO ] (Bottom-Left) */}
            <div className="hud-badge bottom-left absolute bottom-6 left-0 sm:bottom-16 sm:-left-4 z-20 flex items-center gap-1.5 sm:gap-2 px-2 py-0.5 sm:px-2.5 sm:py-1 rounded-md bg-[#071929]/90 border border-indigo-500/40 shadow-[0_0_12px_rgba(99,102,241,0.2)]">
              <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse" />
              <span className="font-mono text-[9px] sm:text-[10px] text-indigo-200 font-semibold tracking-wider">
                DEEPFAKE / MEDIA
              </span>
            </div>

            {/* Bottom Engine Telemetry Status */}
            <div className="absolute -bottom-8 sm:-bottom-10 left-1/2 -translate-x-1/2 sm:left-auto sm:translate-x-0 sm:right-6 z-20 flex items-center gap-2 px-2.5 py-1 sm:px-3 sm:py-1.5 rounded-md bg-[#030e1a]/90 border border-slate-700/60 font-mono text-[9px] sm:text-[10px] text-slate-300 whitespace-nowrap shadow-lg">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
                <span className="text-slate-400">DEFENSE ENGINE v2.4</span>
              </div>
              <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/30">
                ONLINE
              </span>
            </div>

          </div>
        </div>
      </main>

      {/* Footer System Status Bar */}
      <footer className="relative z-20 w-full px-4 sm:px-8 py-3 border-t border-slate-800/60 bg-[#030a13]/70 backdrop-blur-sm flex flex-col sm:flex-row flex-wrap items-center justify-between text-[11px] sm:text-xs font-mono text-slate-400 gap-2 sm:gap-4 text-center sm:text-left">
        <div className="flex items-center justify-center sm:justify-start gap-3 sm:gap-6 flex-wrap">
          <span className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            BPUT CYBER DEFENSE INITIATIVE
          </span>
          <span className="hidden sm:inline text-slate-600">|</span>
          <span className="hidden sm:inline text-slate-400">
            LOCAL & DISTRIBUTED HYBRID SENSORS
          </span>
        </div>

        <div className="flex items-center justify-center sm:justify-end gap-3 sm:gap-5 flex-wrap">
          <span className="text-slate-400">Authenticated access required</span>
          <button 
            onClick={handleLaunch} 
            className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 transition-colors"
          >
            <span>Open Command View</span>
            <ChevronRight size={13} />
          </button>
        </div>
      </footer>

      {/* Auth / Credentials Modal */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 bg-black/85 backdrop-blur-md overflow-y-auto">
          <div className="relative w-full max-w-md md:max-w-2xl lg:max-w-3xl max-h-[96dvh] sm:max-h-[92vh] overflow-y-auto p-3.5 sm:p-6 rounded-2xl bg-[#081726] border border-cyan-500/30 shadow-[0_0_50px_rgba(6,182,212,0.25)] space-y-3 sm:space-y-4 my-auto">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5 sm:pb-3">
              <div className="flex items-center gap-2.5 sm:gap-3">
                <div className="p-1.5 sm:p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shrink-0">
                  <Shield size={18} className="sm:w-5 sm:h-5" />
                </div>
                <div>
                  <h3 className="text-sm sm:text-base font-bold text-white flex items-center gap-2">
                    SOC Authentication
                    <span className="hidden sm:inline-block px-1.5 py-0.5 rounded text-[9px] font-mono border border-emerald-500/30 bg-emerald-950/40 text-emerald-400 font-semibold">
                      v2.4
                    </span>
                  </h3>
                  <p className="text-[10px] sm:text-xs text-slate-400">CyberGuard Operations Center Access</p>
                </div>
              </div>
              <button 
                onClick={() => setShowAuthModal(false)}
                className="text-slate-400 hover:text-white text-base sm:text-lg font-mono p-1 rounded-lg hover:bg-slate-800/60 transition-colors"
                title="Close"
              >
                ✕
              </button>
            </div>

            {/* Mobile Tab Switcher (< md) */}
            <div className="flex md:hidden items-center p-0.5 rounded-lg bg-[#040c17] border border-slate-800 text-xs font-mono">
              <button
                type="button"
                onClick={() => setAuthModalTab('login')}
                className={`flex-1 py-1.5 rounded-md text-center transition-all ${
                  authModalTab === 'login'
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => setAuthModalTab('request')}
                className={`flex-1 py-1.5 rounded-md text-center transition-all ${
                  authModalTab === 'request'
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Request Access
              </button>
            </div>

            {/* Modal Body: 2 Columns on Desktop/Tablet (md+), Single Tab on Mobile (< md) */}
            <div className="md:grid md:grid-cols-2 md:gap-6 items-start">
              {/* Left Column: Sign In Form & Google Auth */}
              <div className={`${authModalTab === 'login' ? 'block' : 'hidden'} md:block space-y-3`}>
                {/* Google Authentication Option */}
                <button
                  type="button"
                  onClick={handleGoogleSignIn}
                  disabled={authLoading || googleLoading}
                  className="w-full py-2 sm:py-2.5 px-3 sm:px-4 rounded-xl bg-slate-900/90 hover:bg-slate-800/90 border border-slate-700/80 hover:border-cyan-500/50 text-white text-xs sm:text-sm font-semibold flex items-center justify-center gap-2.5 sm:gap-3 transition-all duration-200 shadow-sm disabled:opacity-50 active:scale-[0.99]"
                >
                  <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
                  </svg>
                  <span>{googleLoading ? 'Signing in with Google...' : 'Continue with Google'}</span>
                </button>

                <div className="relative flex items-center justify-center my-1.5">
                  <div className="border-t border-slate-800 w-full" />
                  <span className="bg-[#081726] px-2 text-[9px] sm:text-[10px] uppercase tracking-wider font-mono text-slate-500 whitespace-nowrap">
                    or sign in with credentials
                  </span>
                  <div className="border-t border-slate-800 w-full" />
                </div>

                {!otpChallenge ? (
                  <form onSubmit={handleManualLogin} className="space-y-2.5 sm:space-y-3">
                    <div>
                      <label className="block text-[10px] sm:text-[11px] font-mono text-slate-300 mb-1">USERNAME</label>
                      <input
                        type="text"
                        value={loginUsername}
                        onChange={(e) => setLoginUsername(e.target.value)}
                        placeholder="Configured username"
                        className="w-full px-3 py-1.5 sm:py-2 rounded-lg bg-[#040c17] border border-slate-700 text-white font-mono text-xs sm:text-sm focus:border-cyan-500 focus:outline-none transition-colors"
                      />
                    </div>

                    <div>
                      <label className="block text-[10px] sm:text-[11px] font-mono text-slate-300 mb-1">PASSWORD</label>
                      <input
                        type="password"
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                        placeholder="Configured password"
                        className="w-full px-3 py-1.5 sm:py-2 rounded-lg bg-[#040c17] border border-slate-700 text-white font-mono text-xs sm:text-sm focus:border-cyan-500 focus:outline-none transition-colors"
                      />
                    </div>

                    {authError && (
                      <div className="p-2 sm:p-2.5 rounded-lg bg-rose-950/40 border border-rose-500/30 text-[11px] sm:text-xs text-rose-300 font-mono space-y-1">
                        <div className="flex items-start gap-1.5">
                          <AlertTriangle size={14} className="text-rose-400 mt-0.5 shrink-0" />
                          <span className="leading-snug">{authError}</span>
                        </div>
                        {authError.includes('Backend unreachable') && (
                          <div className="pt-1 border-t border-rose-800/40 flex items-center justify-between text-[10px]">
                            <span className="text-slate-400">Target: <code className="text-cyan-300">{apiBaseUrl}</code></span>
                            <button
                              type="button"
                              onClick={() => setShowServerConfig(!showServerConfig)}
                              className="text-cyan-400 hover:text-cyan-300 underline font-sans"
                            >
                              {showServerConfig ? 'Hide Settings' : 'Change Backend'}
                            </button>
                          </div>
                        )}
                      </div>
                    )}

                    {showServerConfig && (
                      <div className="p-2.5 rounded-lg bg-[#030914] border border-cyan-800/50 text-xs font-mono space-y-2">
                        <div className="flex justify-between items-center text-slate-300 text-[10px]">
                          <span className="font-semibold text-cyan-400">CONFIGURE BACKEND URL</span>
                          <button type="button" onClick={() => setShowServerConfig(false)} className="text-slate-400 hover:text-white">✕</button>
                        </div>
                        <input
                          type="url"
                          value={serverEndpointInput}
                          onChange={(e) => setServerEndpointInput(e.target.value)}
                          placeholder="https://cyberguard-backend.onrender.com"
                          className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 text-white text-xs focus:border-cyan-400 focus:outline-none"
                        />
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => {
                              setApiBaseUrl(serverEndpointInput);
                              window.location.reload();
                            }}
                            className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-[10px] font-bold transition-colors"
                          >
                            Save & Reconnect
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setApiBaseUrl('');
                              window.location.reload();
                            }}
                            className="px-2 py-1 rounded border border-slate-700 text-slate-400 hover:text-white text-[10px] transition-colors"
                          >
                            Reset
                          </button>
                        </div>
                      </div>
                    )}

                    <div className="pt-1 flex items-center gap-2 sm:gap-3">
                      <button
                        type="button"
                        onClick={() => setShowAuthModal(false)}
                        className="flex-1 py-2 sm:py-2.5 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 text-xs sm:text-sm font-medium transition-colors"
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        disabled={authLoading}
                        className="flex-1 py-2 sm:py-2.5 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-bold text-xs sm:text-sm shadow-[0_0_20px_rgba(16,185,129,0.3)] transition-all flex items-center justify-center gap-1.5"
                      >
                        {authLoading ? 'Verifying...' : 'Authenticate'}
                      </button>
                    </div>

                    {/* Mobile helper to switch to request access */}
                    <div className="md:hidden text-center pt-1">
                      <button
                        type="button"
                        onClick={() => setAuthModalTab('request')}
                        className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono underline"
                      >
                        Need an account? Request permission by email →
                      </button>
                    </div>
                  </form>
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
                      className="w-full py-2.5 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 text-slate-950 font-bold text-xs sm:text-sm disabled:opacity-50"
                    >
                      {authLoading ? 'Verifying OTP...' : 'Verify and enter workspace'}
                    </button>
                  </form>
                )}
              </div>

              {/* Right Column: Access Policy & Request Approval */}
              <div className={`${authModalTab === 'request' ? 'block' : 'hidden'} md:block md:border-l md:border-slate-800/80 md:pl-6 space-y-3`}>
                <div className="p-2.5 sm:p-3 rounded-xl bg-slate-900/70 border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
                  <div className="flex justify-between items-center">
                    <span className="text-cyan-400 font-semibold flex items-center gap-1.5 text-[10px] sm:text-[11px]">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                      RESTRICTED ACCESS
                    </span>
                    <button
                      type="button"
                      onClick={() => setShowServerConfig(!showServerConfig)}
                      className="text-[9px] sm:text-[10px] text-slate-400 hover:text-cyan-300 underline"
                    >
                      {apiBaseUrl.replace(/^https?:\/\//, '')}
                    </button>
                  </div>
                  <p className="text-[10px] sm:text-[11px] text-slate-400 leading-snug">
                    Secured by CyberGuard Zero-Trust Gateway. Authorized personnel only.
                  </p>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-white">Request Temporary Access</span>
                    <span className="text-[10px] font-mono text-amber-400/90">Email Approval</span>
                  </div>
                  <p className="text-[10px] sm:text-[11px] text-slate-400 leading-snug">
                    Security owner must approve before an analyst session is granted.
                  </p>
                  <form onSubmit={submitAccessRequest} className="space-y-2">
                    <input
                      required
                      type="email"
                      value={requestEmail}
                      onChange={(event) => setRequestEmail(event.target.value)}
                      placeholder="Your official email address"
                      className="w-full px-2.5 py-1.5 sm:py-2 rounded-lg bg-[#040c17] border border-slate-700 text-white text-xs focus:border-cyan-500 focus:outline-none"
                    />
                    <div className="grid grid-cols-2 gap-2">
                      <input
                        type="text"
                        value={requestName}
                        onChange={(event) => setRequestName(event.target.value)}
                        placeholder="Name (optional)"
                        className="w-full px-2.5 py-1.5 sm:py-2 rounded-lg bg-[#040c17] border border-slate-700 text-white text-xs focus:border-cyan-500 focus:outline-none"
                      />
                      <input
                        type="text"
                        value={requestPurpose}
                        onChange={(event) => setRequestPurpose(event.target.value)}
                        placeholder="Purpose (optional)"
                        className="w-full px-2.5 py-1.5 sm:py-2 rounded-lg bg-[#040c17] border border-slate-700 text-white text-xs focus:border-cyan-500 focus:outline-none"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={requestLoading}
                      className="w-full py-1.5 sm:py-2 rounded-lg border border-amber-400/40 text-amber-300 hover:bg-amber-400/10 disabled:opacity-50 text-xs font-semibold transition-colors"
                    >
                      {requestLoading ? 'Submitting request...' : 'Submit access request'}
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

                {/* Mobile helper to switch back to sign in */}
                <div className="md:hidden text-center pt-1">
                  <button
                    type="button"
                    onClick={() => setAuthModalTab('login')}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono underline"
                  >
                    ← Back to Sign In
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
