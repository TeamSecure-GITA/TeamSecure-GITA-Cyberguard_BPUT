import React, { useState } from 'react';
import axios from 'axios';
import {
  LogIn,
  Shield,
  AlertTriangle,
  Flame,
  UserPlus,
  CheckCircle2,
  Server,
  Eye,
  EyeOff,
  Sparkles,
  ArrowLeft
} from 'lucide-react';
import { getApiBaseUrl, setApiBaseUrl } from '../apiConfig';
import {
  loginWithGoogle,
  loginWithFirebaseEmail,
  registerWithFirebaseEmail,
  sendFirebasePasswordReset,
  formatFirebaseAuthError,
} from '../firebase';

export default function Login({ onLogin, onReturnToPortal }) {
  const [apiBaseUrl, setLocalApiBaseUrl] = useState(() => getApiBaseUrl());
  const [showFirebaseEmail, setShowFirebaseEmail] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);
  const [showForgotPw, setShowForgotPw] = useState(false);
  const [showConfig, setShowConfig] = useState(false);
  const [serverUrlInput, setServerUrlInput] = useState(apiBaseUrl);
  const [showPassword, setShowPassword] = useState(false);

  // Form states with active working defaults
  const [username, setUsername] = useState('teamsecure.project@gmail.com');
  const [password, setPassword] = useState('Secure@9040');
  const [displayName, setDisplayName] = useState('');

  // Status states
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

  // Instant resilient activation
  const activateInstantSession = (role = 'head_admin', selectedUser = username) => {
    const isOwner = (selectedUser || '').toLowerCase().includes('teamsecure') || role === 'head_admin';
    const fallbackSession = {
      access_token: `cyberguard-active-session-${Date.now()}`,
      token_type: 'bearer',
      is_demo: true,
      user: {
        username: selectedUser || 'teamsecure.project@gmail.com',
        role: isOwner ? 'head_admin' : 'lead',
        email: selectedUser && selectedUser.includes('@') ? selectedUser : 'teamsecure.project@gmail.com',
      }
    };
    onLogin(fallbackSession);
  };

  // 1. Google Authentication via Firebase
  const handleGoogleSignIn = async () => {
    setGoogleLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const session = await loginWithGoogle(apiBaseUrl);
      if (session) {
        onLogin(session);
      }
    } catch (err) {
      console.error('Google sign-in error:', err);
      // If popup was closed or network error, provide clear guidance or resilient fallback
      if (err.code === 'auth/popup-closed-by-user') {
        setError('Google sign-in window was closed. Try again or click Instant Demo Access.');
      } else {
        setError(formatFirebaseAuthError(err));
      }
    } finally {
      setGoogleLoading(false);
    }
  };

  // 2. Direct CyberGuard SOC Database / Backend Login
  const handleDatabaseLogin = async (event) => {
    event?.preventDefault();
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/auth/login`, {
        username: username.trim(),
        password
      }, { timeout: 6000 });
      if (response.data) {
        onLogin(response.data);
      }
    } catch (requestError) {
      console.warn('Backend login attempt:', requestError);
      if (!requestError.response) {
        setError(
          `Cannot reach backend at ${apiBaseUrl}. You can continue with Google or click "Activate Instant Session" below.`
        );
      } else if (requestError.response.status === 401) {
        setError(requestError.response.data?.detail || 'Invalid username or password. Check credentials or use the role presets.');
      } else if (requestError.response.status === 429) {
        setError('Too many attempts. You can click "Instant Activation" to bypass the lock.');
      } else {
        setError(requestError.response.data?.detail || `Login error (HTTP ${requestError.response.status}).`);
      }
    } finally {
      setLoading(false);
    }
  };

  // 3. Firebase Email/Password Auth (Secondary / Alternate)
  const handleFirebaseEmailAuth = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      let session;
      if (isRegistering) {
        session = await registerWithFirebaseEmail(username, password, displayName, apiBaseUrl);
        setSuccessMsg('Account created successfully via Firebase!');
      } else {
        session = await loginWithFirebaseEmail(username, password, apiBaseUrl);
      }
      if (session) {
        onLogin(session);
      }
    } catch (err) {
      console.error('Firebase email auth error:', err);
      setError(formatFirebaseAuthError(err));
    } finally {
      setLoading(false);
    }
  };

  // 4. Password Reset via Firebase
  const handlePasswordReset = async (e) => {
    e.preventDefault();
    if (!username || !username.includes('@')) {
      setError('Please enter a valid email address to reset password.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await sendFirebasePasswordReset(username);
      setSuccessMsg(`Password reset email sent to ${username}. Check your inbox.`);
      setShowForgotPw(false);
    } catch (err) {
      setError(formatFirebaseAuthError(err));
    } finally {
      setLoading(false);
    }
  };

  const handleRolePreset = (presetUser, presetPass) => {
    setUsername(presetUser);
    setPassword(presetPass);
    setError(null);
  };

  const handleSaveServerUrl = () => {
    if (serverUrlInput && serverUrlInput.trim()) {
      setApiBaseUrl(serverUrlInput.trim());
      setLocalApiBaseUrl(serverUrlInput.trim());
      setShowConfig(false);
      setSuccessMsg(`Backend URL updated to ${serverUrlInput.trim()}`);
    }
  };

  return (
    <main className="min-h-screen w-full bg-[#030914] text-slate-100 flex items-center justify-center p-3 sm:p-4 selection:bg-cyan-500 selection:text-black">
      {/* Background ambient neon mesh */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden opacity-25">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[480px] h-[480px] bg-gradient-to-tr from-cyan-600/25 via-blue-600/15 to-emerald-500/15 rounded-full blur-[110px]" />
      </div>

      {/* Compact Center-Aligned Login Card */}
      <div className="relative z-10 w-full max-w-[390px] sm:max-w-[410px] mx-auto bg-[#081526]/95 backdrop-blur-xl border border-cyan-500/30 rounded-2xl p-5 sm:p-6 shadow-[0_0_50px_rgba(6,182,212,0.2)] space-y-4 my-auto animate-in fade-in zoom-in-95 duration-200">
        
        {/* Header with Return to Portal */}
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.2)] shrink-0">
              <Shield size={20} className="text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <h1 className="text-base font-black text-white tracking-wide">CYBERGUARD AI</h1>
                <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 text-[9px] font-mono font-bold tracking-wider">
                  v2.0
                </span>
              </div>
              <p className="text-[11px] text-slate-400">SOC Operations Center Access</p>
            </div>
          </div>

          {onReturnToPortal && (
            <button
              type="button"
              id="return-to-portal-btn"
              onClick={onReturnToPortal}
              className="text-xs text-slate-400 hover:text-cyan-300 font-mono flex items-center gap-1 transition-colors"
              title="Return to Threat Radar Portal"
            >
              <ArrowLeft size={13} />
              <span>Portal</span>
            </button>
          )}
        </div>

        {/* Feedback Alerts */}
        {error && (
          <div className="p-2.5 rounded-xl bg-rose-950/40 border border-rose-500/40 text-xs text-rose-200 space-y-2 animate-in fade-in duration-150">
            <div className="flex items-start gap-2">
              <AlertTriangle size={15} className="text-rose-400 mt-0.5 shrink-0" />
              <div className="leading-snug flex-1">{error}</div>
            </div>
            <div className="pt-1.5 border-t border-rose-800/40 flex items-center justify-between gap-2">
              <span className="text-[10px] text-slate-300">Quick Solution:</span>
              <button
                type="button"
                onClick={() => activateInstantSession('head_admin')}
                className="px-2 py-0.5 rounded bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-[10px] flex items-center gap-1 cursor-pointer transition-colors"
              >
                <Sparkles size={11} />
                <span>Activate Instant Session</span>
              </button>
            </div>
          </div>
        )}

        {successMsg && (
          <div className="p-2.5 rounded-xl bg-emerald-950/40 border border-emerald-500/40 text-xs text-emerald-200 flex items-center gap-2 animate-in fade-in duration-150">
            <CheckCircle2 size={15} className="text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Primary Action 1: Sign in with Google (Prominent, Top-level) */}
        <div className="space-y-2">
          <button
            type="button"
            id="google-login-btn"
            onClick={handleGoogleSignIn}
            disabled={googleLoading || loading}
            aria-label="Sign in with Google"
            className="w-full py-2.5 px-3 rounded-xl bg-[#0b1b2d] hover:bg-[#10243d] border border-slate-700/80 hover:border-cyan-400 text-white text-xs sm:text-sm font-semibold flex items-center justify-center gap-2.5 transition-all shadow-md hover:shadow-cyan-500/20 active:scale-[0.99] cursor-pointer group"
          >
            {/* Multi-colored Google Icon */}
            <svg className="w-4 h-4 shrink-0 transition-transform group-hover:scale-110" viewBox="0 0 24 24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
            </svg>
            <span>{googleLoading ? 'Connecting to Google...' : 'Continue with Google'}</span>
          </button>
          <p className="text-[10px] text-center text-slate-400">
            One-click sign-in via Google Cloud Identity & Firebase
          </p>
        </div>

        {/* Divider */}
        <div className="relative flex items-center justify-center my-2">
          <div className="border-t border-slate-800 w-full" />
          <span className="bg-[#081526] px-2 text-[10px] uppercase tracking-wider font-mono text-slate-500 whitespace-nowrap">
            or sign in with credentials
          </span>
          <div className="border-t border-slate-800 w-full" />
        </div>

        {/* Quick Role Fill Chips */}
        <div className="flex items-center justify-between gap-1.5 text-[10px] font-mono">
          <span className="text-slate-400">Presets:</span>
          <div className="flex gap-1">
            <button
              type="button"
              onClick={() => handleRolePreset('teamsecure.project@gmail.com', 'Secure@9040')}
              className={`px-1.5 py-0.5 rounded border transition-colors ${
                username === 'teamsecure.project@gmail.com'
                  ? 'border-cyan-500 bg-cyan-950/60 text-cyan-300 font-bold'
                  : 'border-slate-800 bg-slate-900/60 text-slate-400 hover:text-white'
              }`}
            >
              Head Admin
            </button>
            <button
              type="button"
              onClick={() => handleRolePreset('lead', 'Secure@9040')}
              className={`px-1.5 py-0.5 rounded border transition-colors ${
                username === 'lead'
                  ? 'border-cyan-500 bg-cyan-950/60 text-cyan-300 font-bold'
                  : 'border-slate-800 bg-slate-900/60 text-slate-400 hover:text-white'
              }`}
            >
              Lead
            </button>
            <button
              type="button"
              onClick={() => handleRolePreset('analyst', 'Secure@9040')}
              className={`px-1.5 py-0.5 rounded border transition-colors ${
                username === 'analyst'
                  ? 'border-cyan-500 bg-cyan-950/60 text-cyan-300 font-bold'
                  : 'border-slate-800 bg-slate-900/60 text-slate-400 hover:text-white'
              }`}
            >
              Analyst
            </button>
          </div>
        </div>

        {/* Credentials Form */}
        {!showFirebaseEmail ? (
          <form onSubmit={handleDatabaseLogin} className="space-y-3">
            <div>
              <label className="block text-[11px] font-semibold text-slate-300 mb-1">
                Username or Email
              </label>
              <input
                required
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="teamsecure.project@gmail.com"
                className="w-full bg-[#040c17] border border-slate-700/80 rounded-lg px-3 py-2 text-xs sm:text-sm text-white font-mono focus:border-cyan-500 focus:outline-none transition-colors"
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-[11px] font-semibold text-slate-300">
                  Password
                </label>
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="text-[10px] text-slate-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                >
                  {showPassword ? <EyeOff size={12} /> : <Eye size={12} />}
                  <span>{showPassword ? 'Hide' : 'Show'}</span>
                </button>
              </div>
              <input
                required
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Secure@9040"
                className="w-full bg-[#040c17] border border-slate-700/80 rounded-lg px-3 py-2 text-xs sm:text-sm text-white font-mono focus:border-cyan-500 focus:outline-none transition-colors"
              />
            </div>

            {/* Primary Sign In Button */}
            <button
              type="submit"
              id="submit-login-btn"
              disabled={loading || googleLoading}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 via-cyan-500 to-blue-500 hover:from-emerald-400 hover:to-cyan-400 disabled:opacity-50 text-slate-950 text-xs sm:text-sm font-bold flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(16,185,129,0.25)] transition-all cursor-pointer active:scale-[0.99]"
            >
              {loading ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                  <span>Verifying Credentials...</span>
                </>
              ) : (
                <>
                  <LogIn size={15} />
                  <span>Sign In & Activate Workspace</span>
                </>
              )}
            </button>

            {/* Instant Demo Session Fallback Button */}
            <button
              type="button"
              id="instant-activate-btn"
              onClick={() => activateInstantSession('head_admin')}
              className="w-full py-2 rounded-xl bg-slate-900/80 hover:bg-slate-800 border border-emerald-500/40 text-emerald-400 hover:text-emerald-300 text-xs font-mono font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
              title="Bypass login barriers and enter workspace directly"
            >
              <Sparkles size={13} className="text-emerald-400" />
              <span>Instant Access (1-Click Activate)</span>
            </button>
          </form>
        ) : (
          /* Firebase Email Mode Toggle */
          <div className="space-y-3">
            {!showForgotPw ? (
              <form onSubmit={handleFirebaseEmailAuth} className="space-y-2.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-white">
                    {isRegistering ? 'Register Firebase Account' : 'Firebase Email Sign-In'}
                  </span>
                  <span className="text-[10px] font-mono text-amber-400 flex items-center gap-1">
                    <Flame size={12} />
                    Firebase
                  </span>
                </div>

                {isRegistering && (
                  <input
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    placeholder="Full Name / Call-Sign"
                    className="w-full bg-[#040c17] border border-slate-700/80 rounded-lg p-2 text-xs text-white focus:border-amber-400 focus:outline-none"
                  />
                )}

                <input
                  required
                  type="email"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="analyst@example.com"
                  className="w-full bg-[#040c17] border border-slate-700/80 rounded-lg p-2 text-xs text-white focus:border-amber-400 focus:outline-none"
                />

                <input
                  required
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-[#040c17] border border-slate-700/80 rounded-lg p-2 text-xs text-white focus:border-amber-400 focus:outline-none"
                />

                <div className="flex items-center justify-between text-[10px]">
                  <button
                    type="button"
                    onClick={() => setShowForgotPw(true)}
                    className="text-slate-400 hover:text-amber-300 underline font-mono"
                  >
                    Forgot password?
                  </button>
                  <button
                    type="button"
                    onClick={() => { setIsRegistering(!isRegistering); setError(null); }}
                    className="text-amber-400 hover:text-amber-300 font-semibold"
                  >
                    {isRegistering ? 'Have an account? Sign in' : 'Create new account'}
                  </button>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                >
                  {isRegistering ? <UserPlus size={14} /> : <LogIn size={14} />}
                  <span>{loading ? 'Processing...' : isRegistering ? 'Create Account' : 'Sign In with Firebase'}</span>
                </button>
              </form>
            ) : (
              <form onSubmit={handlePasswordReset} className="space-y-2.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-white">Reset Password</span>
                  <button
                    type="button"
                    onClick={() => setShowForgotPw(false)}
                    className="text-xs text-slate-400 hover:text-white"
                  >
                    ✕ Cancel
                  </button>
                </div>
                <input
                  required
                  type="email"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="analyst@example.com"
                  className="w-full bg-[#040c17] border border-slate-700 rounded-lg p-2 text-xs text-white focus:border-amber-400 focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs transition-colors"
                >
                  {loading ? 'Sending...' : 'Send Reset Link'}
                </button>
              </form>
            )}
          </div>
        )}

        {/* Footer toggles */}
        <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
          <button
            type="button"
            onClick={() => setShowFirebaseEmail(!showFirebaseEmail)}
            className="text-slate-400 hover:text-cyan-300 underline transition-colors"
          >
            {showFirebaseEmail ? '← Standard Sign In' : 'Firebase Email Auth →'}
          </button>

          <button
            type="button"
            onClick={() => setShowConfig(!showConfig)}
            className="text-cyan-400 hover:text-cyan-300 underline flex items-center gap-1"
          >
            <Server size={10} />
            <span>{showConfig ? 'Close' : 'Backend URL'}</span>
          </button>
        </div>

        {/* Backend Target Settings */}
        {showConfig && (
          <div className="p-2.5 rounded-xl bg-[#030914] border border-cyan-800/50 space-y-2 text-xs animate-in fade-in duration-150">
            <label className="block text-[10px] font-mono text-slate-300">
              FASTAPI BACKEND URL
              <input
                type="url"
                value={serverUrlInput}
                onChange={(e) => setServerUrlInput(e.target.value)}
                placeholder="http://127.0.0.1:8000"
                className="mt-1 w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-xs text-white focus:border-cyan-400 focus:outline-none font-mono"
              />
            </label>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={handleSaveServerUrl}
                className="flex-1 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-[10px]"
              >
                Apply
              </button>
              <button
                type="button"
                onClick={() => {
                  setServerUrlInput('http://127.0.0.1:8000');
                  setApiBaseUrl('http://127.0.0.1:8000');
                  setLocalApiBaseUrl('http://127.0.0.1:8000');
                  setShowConfig(false);
                }}
                className="px-2 py-1 rounded border border-slate-700 text-slate-400 text-[10px]"
              >
                Reset
              </button>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
