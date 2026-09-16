import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  ArrowRight, 
  Radio, 
  Lock, 
  Globe, 
  Cpu, 
  Activity, 
  Terminal, 
  Eye, 
  Zap, 
  AlertTriangle,
  Server,
  Layers,
  ChevronRight,
  Sparkles,
  ExternalLink
} from 'lucide-react';
import LanguageToggle from './LanguageToggle';

export default function CyberRadarPortal({ onOpenWorkspace, onQuickLogin, currentSession, currentLang, onLanguageChange }) {
  const [telemetry, setTelemetry] = useState({
    lat: 12.44,
    freq: 4.82,
    threatsBlocked: 1420,
    activeNodes: 64,
    status: 'OPTIMAL'
  });

  const [activeBlip, setActiveBlip] = useState(null);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [loginUsername, setLoginUsername] = useState('teamsecure.project@gmail.com');
  const [loginPassword, setLoginPassword] = useState('Secure@9040');
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState(null);

  // Dynamic telemetry pulse simulation
  useEffect(() => {
    const interval = setInterval(() => {
      setTelemetry((prev) => ({
        ...prev,
        lat: +(12.2 + Math.random() * 0.5).toFixed(2),
        threatsBlocked: prev.threatsBlocked + (Math.random() > 0.6 ? 1 : 0),
      }));
    }, 2400);
    return () => clearInterval(interval);
  }, []);

  const handleLaunch = () => {
    if (currentSession) {
      onOpenWorkspace();
    } else {
      // Auto-authenticate as Senior SOC Lead or open workspace
      if (onQuickLogin) {
        onQuickLogin('teamsecure.project@gmail.com', 'Secure@9040');
      } else {
        onOpenWorkspace();
      }
    }
  };

  const handleManualLogin = async (e) => {
    e.preventDefault();
    setAuthLoading(true);
    setAuthError(null);
    try {
      if (onQuickLogin) {
        await onQuickLogin(loginUsername, loginPassword);
        setShowAuthModal(false);
      } else {
        onOpenWorkspace();
      }
    } catch (err) {
      setAuthError('Authentication failed. Check credentials.');
    } finally {
      setAuthLoading(false);
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
      <header className="relative z-20 w-full px-8 py-5 flex items-center justify-between border-b border-cyan-500/10 backdrop-blur-md bg-[#040c17]/60">
        {/* Brand Logo */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-400/20 via-cyan-500/20 to-transparent border border-emerald-400/40 p-0.5 shadow-[0_0_20px_rgba(16,185,129,0.3)] flex items-center justify-center">
            <div className="w-full h-full rounded-[10px] bg-[#061826] flex items-center justify-center">
              <span className="font-mono font-black text-emerald-400 text-xl tracking-tighter shadow-sm">C</span>
            </div>
          </div>
          <div className="flex flex-col">
            <span className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              CyberGuard <span className="text-emerald-400 font-semibold">AI</span>
            </span>
          </div>
        </div>

        {/* Real-time Status Badge & Controls */}
        <div className="flex items-center gap-4">
          <LanguageToggle currentLang={currentLang} onToggle={onLanguageChange} />
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-emerald-500/30 bg-emerald-950/30 text-emerald-400 font-mono text-xs tracking-wider shadow-[0_0_15px_rgba(16,185,129,0.15)]">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="font-semibold">[ • REAL-TIME INTELLIGENCE ACTIVE ]</span>
          </div>

          <button
            onClick={() => setShowAuthModal(true)}
            className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700/80 bg-slate-800/40 text-xs font-mono text-slate-300 hover:text-cyan-300 hover:border-cyan-500/40 transition-all"
            title="Custom Credentials"
          >
            <Lock size={12} className="text-cyan-400" />
            <span>{currentSession ? `Signed in: ${currentSession.user?.username || 'SOC Lead'}` : 'SOC Login'}</span>
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
          <div className="pt-2 flex flex-col sm:flex-row items-start sm:items-center gap-4 w-full">
            <button
              id="open-detection-workspace-btn"
              onClick={handleLaunch}
              className="group relative inline-flex items-center justify-center gap-3 px-8 py-4 rounded-xl font-medium text-slate-950 font-semibold text-base transition-all duration-300 shadow-[0_0_30px_rgba(16,185,129,0.45)] hover:shadow-[0_0_45px_rgba(6,182,212,0.65)] hover:scale-[1.02] active:scale-[0.98]"
              style={{
                background: 'linear-gradient(135deg, #34d399 0%, #10b981 40%, #06b6d4 100%)',
              }}
            >
              <span className="relative z-10 tracking-wide font-bold text-[#041d1a]">
                Open detection workspace
              </span>
              <ArrowRight 
                size={19} 
                className="relative z-10 text-[#041d1a] transition-transform duration-300 group-hover:translate-x-1.5" 
              />
              {/* Button neon sheen */}
              <span className="absolute inset-0 rounded-xl bg-white/20 opacity-0 group-hover:opacity-100 transition-opacity" />
            </button>

            {currentSession && (
              <span className="text-xs font-mono text-emerald-400/90 flex items-center gap-1.5 px-3 py-2 rounded-lg bg-emerald-950/40 border border-emerald-500/20">
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
        <div className="flex-1 w-full max-w-[560px] flex items-center justify-center relative min-h-[460px]">
          
          {/* Main Gyroscope Container */}
          <div className="relative w-[380px] h-[380px] sm:w-[440px] sm:h-[440px] flex items-center justify-center">
            
            {/* Outer Static HUD Range Rings */}
            <div className="absolute inset-0 rounded-full border border-cyan-500/15" />
            <div className="absolute inset-8 rounded-full border border-emerald-500/20 border-dashed animate-[spin_120s_linear_infinite]" />
            <div className="absolute inset-20 rounded-full border border-cyan-400/25" />

            {/* Crosshair grid lines */}
            <div className="absolute w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-500/20 to-transparent pointer-events-none" />
            <div className="absolute h-full w-[1px] bg-gradient-to-b from-transparent via-cyan-500/20 to-transparent pointer-events-none" />

            {/* Radar Sweeper Line (Conic gradient rotation) */}
            <div 
              className="absolute inset-4 rounded-full pointer-events-none animate-[radar-sweep_5s_linear_infinite]"
              style={{
                background: 'conic-gradient(from 0deg, rgba(16, 185, 129, 0.28) 0deg, rgba(6, 182, 212, 0.08) 45deg, transparent 90deg, transparent 360deg)'
              }}
            />

            {/* 3D Gyroscope Orbital Ring 1: Tilted Positive Axis */}
            <div 
              className="gyro-orbit-ring gyro-ring-1 absolute w-[380px] h-[190px] sm:w-[420px] sm:h-[210px] rounded-[50%] border-2 border-emerald-400/40 pointer-events-none"
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
              className="gyro-orbit-ring gyro-ring-2 absolute w-[360px] h-[180px] sm:w-[400px] sm:h-[200px] rounded-[50%] border-2 border-cyan-400/45 pointer-events-none"
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
              className="gyro-orbit-ring gyro-ring-3 absolute w-[320px] h-[160px] sm:w-[360px] sm:h-[180px] rounded-[50%] border border-teal-300/35 pointer-events-none"
              style={{
                boxShadow: '0 0 15px rgba(45, 212, 191, 0.2)',
                transform: 'rotateX(74deg) rotateY(42deg) rotateZ(-30deg)',
              }}
            />

            {/* Central Holographic Core Badge */}
            <div 
              onClick={handleLaunch}
              className="group cursor-pointer relative z-20 w-32 h-32 sm:w-36 sm:h-36 rounded-full flex flex-col items-center justify-center backdrop-blur-xl transition-all duration-300 hover:scale-105"
              style={{
                background: 'radial-gradient(circle, rgba(16, 185, 129, 0.32) 0%, rgba(6, 24, 38, 0.88) 75%, rgba(4, 12, 23, 0.95) 100%)',
                border: '2px solid rgba(52, 211, 153, 0.65)',
                boxShadow: '0 0 45px rgba(16, 185, 129, 0.5), inset 0 0 30px rgba(16, 185, 129, 0.35)',
              }}
            >
              {/* Inner Pulsing Radar Glow */}
              <div className="absolute inset-2 rounded-full border border-emerald-400/40 animate-ping opacity-25 pointer-events-none" />
              
              {/* Monogram Glyph */}
              <span className="text-3xl sm:text-4xl font-extrabold tracking-wider text-white drop-shadow-[0_0_15px_rgba(255,255,255,0.8)]">
                CG
              </span>
              
              {/* Live Latency Telemetry Readout */}
              <div className="mt-1 flex items-center gap-1 text-[10px] font-mono text-emerald-300 tracking-wider">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                <span>LAT: {telemetry.lat}ms</span>
              </div>
            </div>

            {/* Floating Cyber HUD Telemetry Tags with Tracer Lines */}

            {/* Tag 1: [ URL / WEB ] (Top-Left) */}
            <div className="hud-badge top-left absolute -top-2 left-2 sm:-top-4 sm:left-4 z-20 flex items-center gap-2 px-2.5 py-1 rounded-md bg-[#071929]/80 border border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.2)]">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              <span className="font-mono text-[10px] text-cyan-200 font-semibold tracking-wider">
                URL / WEB
              </span>
              {/* Leader pin line pointing towards core */}
              <div className="hidden sm:block absolute right-[-24px] bottom-[-14px] w-6 h-[1px] bg-cyan-500/40 rotate-[35deg]" />
            </div>

            {/* Tag 2: [ IP / SCAN ] (Top-Right) */}
            <div className="hud-badge top-right absolute top-6 -right-2 sm:top-4 sm:-right-6 z-20 flex items-center gap-2 px-2.5 py-1 rounded-md bg-[#071929]/80 border border-emerald-500/40 shadow-[0_0_12px_rgba(16,185,129,0.2)]">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="font-mono text-[10px] text-emerald-200 font-semibold tracking-wider">
                IP / SCAN
              </span>
              {/* Leader pin line */}
              <div className="hidden sm:block absolute left-[-24px] bottom-[-14px] w-6 h-[1px] bg-emerald-500/40 -rotate-[35deg]" />
            </div>

            {/* Tag 3: [ TOR / RELAY ] (Bottom-Right) */}
            <div className="hud-badge bottom-right absolute bottom-12 -right-4 sm:bottom-14 sm:-right-8 z-20 flex items-center gap-2 px-2.5 py-1 rounded-md bg-[#071929]/80 border border-amber-500/40 shadow-[0_0_12px_rgba(245,158,11,0.2)]">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
              <span className="font-mono text-[10px] text-amber-200 font-semibold tracking-wider">
                TOR / RELAY
              </span>
              {/* Leader pin line */}
              <div className="hidden sm:block absolute left-[-22px] top-[-10px] w-6 h-[1px] bg-amber-500/40 rotate-[30deg]" />
            </div>

            {/* Tag 4: [ DEEPFAKE / AUDIO ] (Bottom-Left) */}
            <div className="hud-badge bottom-left absolute bottom-14 -left-2 sm:bottom-16 sm:-left-6 z-20 flex items-center gap-2 px-2.5 py-1 rounded-md bg-[#071929]/80 border border-indigo-500/40 shadow-[0_0_12px_rgba(99,102,241,0.2)]">
              <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse" />
              <span className="font-mono text-[10px] text-indigo-200 font-semibold tracking-wider">
                DEEPFAKE / MEDIA
              </span>
            </div>

            {/* Bottom Engine Telemetry Status */}
            <div className="absolute -bottom-10 right-0 sm:right-6 z-20 flex items-center gap-3 px-3 py-1.5 rounded-md bg-[#030e1a]/85 border border-slate-700/60 font-mono text-[10px] text-slate-300">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
                <span className="text-slate-400">ADAPTIVE DEFENSE ENGINE v2.4</span>
              </div>
              <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/30">
                ONLINE
              </span>
            </div>

          </div>
        </div>
      </main>

      {/* Footer System Status Bar */}
      <footer className="relative z-20 w-full px-8 py-3 border-t border-slate-800/60 bg-[#030a13]/70 backdrop-blur-sm flex flex-wrap items-center justify-between text-xs font-mono text-slate-400 gap-4">
        <div className="flex items-center gap-6">
          <span className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            BPUT CYBER DEFENSE INITIATIVE
          </span>
          <span className="hidden sm:inline text-slate-600">|</span>
          <span className="hidden sm:inline text-slate-400">
            ACTIVE SENSORS: <b className="text-cyan-300 font-normal">24/24 ONLINE</b>
          </span>
        </div>

        <div className="flex items-center gap-5">
          <span className="text-slate-400">
            THREAT MITIGATIONS: <b className="text-emerald-400">{telemetry.threatsBlocked.toLocaleString()}</b>
          </span>
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
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md">
          <div className="relative w-full max-w-md p-6 rounded-2xl bg-[#081726] border border-cyan-500/30 shadow-[0_0_50px_rgba(6,182,212,0.25)] space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  <Shield size={20} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">SOC Authentication</h3>
                  <p className="text-xs text-slate-400">Access CyberGuard Operations Center</p>
                </div>
              </div>
              <button 
                onClick={() => setShowAuthModal(false)}
                className="text-slate-400 hover:text-white text-lg font-mono px-2"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleManualLogin} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">USERNAME</label>
                <input
                  type="text"
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-lg bg-[#040c17] border border-slate-700 text-white font-mono text-sm focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">PASSWORD</label>
                <input
                  type="password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-lg bg-[#040c17] border border-slate-700 text-white font-mono text-sm focus:border-cyan-500 focus:outline-none"
                />
              </div>

              {authError && (
                <div className="text-xs text-rose-400 font-mono flex items-center gap-2">
                  <AlertTriangle size={14} />
                  <span>{authError}</span>
                </div>
              )}

              <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
                <p className="text-cyan-400 font-semibold">PRESET SOC ACCOUNTS:</p>
                <div className="flex justify-between">
                  <span>Lead SOC (Full Access):</span>
                  <span className="text-slate-300">Head admin / teamsecure.project@gmail.com</span>
                </div>
                <div className="flex justify-between">
                  <span>Tier 1 Analyst (Read-only):</span>
                  <span className="text-slate-300">analyst / analyst123</span>
                </div>
              </div>

              <div className="pt-2 flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setShowAuthModal(false)}
                  className="flex-1 py-2.5 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800 text-sm font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={authLoading}
                  className="flex-1 py-2.5 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-bold text-sm shadow-[0_0_20px_rgba(16,185,129,0.3)] transition-all flex items-center justify-center gap-2"
                >
                  {authLoading ? 'Verifying...' : 'Authenticate'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
