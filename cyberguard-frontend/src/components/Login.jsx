import React, { useState } from 'react';
import axios from 'axios';
import {
  LockKeyhole,
  LogIn,
  Shield,
  AlertTriangle,
  Flame,
  UserPlus,
  KeyRound,
  CheckCircle2,
  Server
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
  const [authMode, setAuthMode] = useState('google'); // 'google', 'firebase-email', 'database'
  const [isRegistering, setIsRegistering] = useState(false);
  const [showForgotPw, setShowForgotPw] = useState(false);
  const [showConfig, setShowConfig] = useState(false);
  const [serverUrlInput, setServerUrlInput] = useState(apiBaseUrl);

  // Form states
  const [username, setUsername] = useState('teamsecure.project@gmail.com');
  const [password, setPassword] = useState('Secure@9040');
  const [displayName, setDisplayName] = useState('');

  // Status states
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

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
      setError(formatFirebaseAuthError(err));
    } finally {
      setGoogleLoading(false);
    }
  };

  // 2. Firebase Email/Password Auth
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

  // 3. Password Reset via Firebase
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

  // 4. Direct CyberGuard SOC Database / Backend Login
  const handleDatabaseLogin = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/auth/login`, { username, password });
      onLogin(response.data);
    } catch (requestError) {
      if (!requestError.response) {
        setError(
          `CORS / Network Error: Cannot reach CyberGuard backend at ${apiBaseUrl}. Ensure the backend service is running (e.g. 'python main.py' or 'npm run backend'). You can also use Google Sign-In below.`
        );
      } else if (requestError.response.status === 401) {
        setError(requestError.response.data?.detail || 'Invalid username or password.');
      } else if (requestError.response.status === 502 || requestError.response.status === 503) {
        setError(`Backend service is temporarily unavailable (HTTP ${requestError.response.status}). Please wait a few seconds and try again.`);
      } else if (requestError.response.data?.detail) {
        setError(requestError.response.data.detail);
      } else {
        setError(`Login failed with HTTP status ${requestError.response.status}.`);
      }
    } finally {
      setLoading(false);
    }
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
    <main className="min-h-screen min-h-[100dvh] w-full bg-[#030914] text-slate-100 flex items-center justify-center p-3 sm:p-6 overflow-y-auto selection:bg-cyan-500 selection:text-black">
      {/* Background ambient neon mesh */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden opacity-30">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-tr from-cyan-600/20 via-blue-600/10 to-emerald-500/15 rounded-full blur-[130px]" />
      </div>

      <div className="relative z-10 w-full max-w-md max-h-[96dvh] overflow-y-auto bg-[#081526]/95 backdrop-blur-xl border border-cyan-500/30 rounded-2xl p-4 sm:p-6 shadow-2xl shadow-cyan-950/60 space-y-4 my-auto">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2.5 sm:gap-3">
            <div className="p-2 sm:p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.2)] shrink-0">
              <Shield size={22} className="text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <h1 className="text-base sm:text-lg font-black text-white tracking-wide">CYBERGUARD AI</h1>
                <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 text-[9px] font-mono font-bold tracking-wider">
                  v2.0
                </span>
              </div>
              <p className="text-[11px] sm:text-xs text-slate-400">Threat Operations & SOC Access</p>
            </div>
          </div>
          {onReturnToPortal && (
            <button
              type="button"
              id="return-to-portal-btn"
              onClick={onReturnToPortal}
              className="text-xs text-slate-400 hover:text-cyan-300 font-mono underline transition-colors"
            >
              ← Portal
            </button>
          )}
        </div>

        {/* Auth Mode Segmented Control */}
        <div className="grid grid-cols-3 gap-1 bg-[#040c17] p-1 rounded-xl border border-slate-800 text-[11px] font-semibold">
          <button
            type="button"
            id="tab-google-auth"
            onClick={() => { setAuthMode('google'); setError(null); }}
            className={`py-1.5 px-2 rounded-lg flex items-center justify-center gap-1.5 transition-all ${
              authMode === 'google'
                ? 'bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            {/* Google Icon Mini */}
            <svg className="w-3.5 h-3.5 shrink-0" viewBox="0 0 24 24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
            </svg>
            <span>Google</span>
          </button>

          <button
            type="button"
            id="tab-firebase-auth"
            onClick={() => { setAuthMode('firebase-email'); setError(null); }}
            className={`py-1.5 px-2 rounded-lg flex items-center justify-center gap-1.5 transition-all ${
              authMode === 'firebase-email'
                ? 'bg-amber-500/15 border border-amber-500/40 text-amber-300 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Flame size={13} className="text-amber-400" />
            <span>Firebase</span>
          </button>

          <button
            type="button"
            id="tab-soc-database"
            onClick={() => { setAuthMode('database'); setError(null); }}
            className={`py-1.5 px-2 rounded-lg flex items-center justify-center gap-1.5 transition-all ${
              authMode === 'database'
                ? 'bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 shadow-sm'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <KeyRound size={13} className="text-emerald-400" />
            <span>SOC DB</span>
          </button>
        </div>

        {/* Feedback Alerts */}
        {error && (
          <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-500/40 text-xs text-rose-200 space-y-2 animate-in fade-in duration-200">
            <div className="flex items-start gap-2">
              <AlertTriangle size={16} className="text-rose-400 mt-0.5 shrink-0" />
              <div className="leading-snug flex-1">{error}</div>
            </div>
            {/* Quick action button for Google Login fallback when backend/CORS error occurs */}
            {(error.includes('CORS') || error.includes('Cannot reach') || error.includes('Network Error')) && (
              <div className="pt-2 border-t border-rose-800/40 flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] text-slate-300">Alternative:</span>
                <button
                  type="button"
                  onClick={handleGoogleSignIn}
                  disabled={googleLoading}
                  className="px-2.5 py-1 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-[11px] flex items-center gap-1.5 transition-all cursor-pointer"
                >
                  <svg className="w-3 h-3 shrink-0" viewBox="0 0 24 24">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
                  </svg>
                  <span>Sign in with Google instead</span>
                </button>
              </div>
            )}
          </div>
        )}

        {successMsg && (
          <div className="p-2.5 rounded-xl bg-emerald-950/40 border border-emerald-500/40 text-xs text-emerald-200 flex items-center gap-2 animate-in fade-in duration-200">
            <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Tab 1: Google One-Click Auth */}
        {authMode === 'google' && (
          <div className="space-y-4 py-1">
            <div className="text-center space-y-1">
              <h2 className="text-sm font-semibold text-white">Google Cloud Identity & Firebase</h2>
              <p className="text-xs text-slate-400">
                Single sign-on authenticated via Google OAuth and Firebase Authenticator.
              </p>
            </div>

            <button
              type="button"
              id="google-login-btn"
              onClick={handleGoogleSignIn}
              disabled={googleLoading}
              aria-label="Sign in with Google"
              title="Sign in with your Google account"
              className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 hover:from-slate-800 hover:to-slate-700 border border-slate-700 hover:border-cyan-400 text-white text-xs sm:text-sm font-semibold flex items-center justify-center gap-3 transition-all duration-200 shadow-lg shadow-cyan-950/30 hover:shadow-cyan-500/20 disabled:opacity-50 active:scale-[0.99] cursor-pointer group"
            >
              <svg className="w-5 h-5 shrink-0 transition-transform group-hover:scale-110" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
              </svg>
              <span className="tracking-wide">
                {googleLoading ? 'Connecting to Google...' : 'Continue with Google'}
              </span>
            </button>

            <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400 space-y-1.5 font-mono">
              <div className="flex items-center gap-1.5 text-cyan-400 font-semibold">
                <Shield size={13} />
                <span>Zero-Trust Role Assignment</span>
              </div>
              <p className="text-[10px] sm:text-[11px] text-slate-400 leading-snug">
                Signing in with <code className="text-amber-300">teamsecure.project@gmail.com</code> automatically provisions full <strong className="text-white">Head Admin</strong> authorization. Other Google accounts receive analyst privileges.
              </p>
            </div>
          </div>
        )}

        {/* Tab 2: Firebase Email/Password Auth */}
        {authMode === 'firebase-email' && (
          <div className="space-y-3">
            {!showForgotPw ? (
              <form onSubmit={handleFirebaseEmailAuth} className="space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-white">
                    {isRegistering ? 'Create Firebase Account' : 'Firebase Email Sign-In'}
                  </span>
                  <span className="text-[10px] font-mono text-amber-400 flex items-center gap-1">
                    <Flame size={12} />
                    Firebase Auth
                  </span>
                </div>

                {isRegistering && (
                  <label className="block text-[11px] font-semibold text-slate-300">
                    Full Name / Call-Sign
                    <input
                      type="text"
                      value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)}
                      placeholder="Security Analyst"
                      className="mt-1 w-full bg-[#040c17] border border-slate-700/80 rounded-lg p-2 text-xs sm:text-sm text-white focus:border-amber-400 focus:outline-none transition-colors"
                    />
                  </label>
                )}

                <label className="block text-[11px] font-semibold text-slate-300">
                  Email Address
                  <input
                    required
                    type="email"
                    autoComplete="email"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="analyst@example.com"
                    className="mt-1 w-full bg-[#040c17] border border-slate-700/80 rounded-lg p-2 text-xs sm:text-sm text-white focus:border-amber-400 focus:outline-none transition-colors"
                  />
                </label>

                <label className="block text-[11px] font-semibold text-slate-300">
                  Password
                  <input
                    required
                    type="password"
                    autoComplete={isRegistering ? 'new-password' : 'current-password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="mt-1 w-full bg-[#040c17] border border-slate-700/80 rounded-lg p-2 text-xs sm:text-sm text-white focus:border-amber-400 focus:outline-none transition-colors"
                  />
                </label>

                <div className="flex items-center justify-between text-[11px]">
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
                  disabled={loading || googleLoading}
                  className="w-full py-2.5 rounded-xl bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 disabled:opacity-50 text-slate-950 text-xs sm:text-sm font-bold flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(245,158,11,0.25)] transition-all cursor-pointer"
                >
                  {isRegistering ? <UserPlus size={16} /> : <LogIn size={16} />}
                  <span>{loading ? 'Authenticating...' : isRegistering ? 'Register with Firebase' : 'Sign in with Firebase'}</span>
                </button>
              </form>
            ) : (
              <form onSubmit={handlePasswordReset} className="space-y-3">
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
                <p className="text-xs text-slate-400 leading-snug">
                  Enter your email address to receive a secure Firebase password reset link.
                </p>
                <input
                  required
                  type="email"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="analyst@example.com"
                  className="w-full bg-[#040c17] border border-slate-700 rounded-lg p-2 text-xs sm:text-sm text-white focus:border-amber-400 focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs transition-colors"
                >
                  {loading ? 'Sending...' : 'Send Password Reset Link'}
                </button>
              </form>
            )}
          </div>
        )}

        {/* Tab 3: Direct SOC Database Login */}
        {authMode === 'database' && (
          <form onSubmit={handleDatabaseLogin} className="space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-white">Direct SOC DB Credentials</span>
              <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                <KeyRound size={12} />
                FastAPI / SQLite
              </span>
            </div>

            <label className="block text-[11px] font-semibold text-slate-300">
              Username or Email
              <input
                required
                autoComplete="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="teamsecure.project@gmail.com"
                className="mt-1 w-full bg-[#040c17] border border-slate-700/80 rounded-lg p-2 text-xs sm:text-sm text-white focus:border-cyan-500 focus:outline-none transition-colors"
              />
            </label>

            <label className="block text-[11px] font-semibold text-slate-300">
              Password
              <input
                required
                autoComplete="current-password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Secure@9040"
                className="mt-1 w-full bg-[#040c17] border border-slate-700/80 rounded-lg p-2 text-xs sm:text-sm text-white focus:border-cyan-500 focus:outline-none transition-colors"
              />
            </label>

            <button
              type="submit"
              disabled={loading || googleLoading}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 disabled:opacity-50 text-slate-950 text-xs sm:text-sm font-bold flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(16,185,129,0.25)] transition-all cursor-pointer"
            >
              <LockKeyhole size={16} />
              <span>{loading ? 'Authenticating with SOC...' : 'Sign in to SOC Engine'}</span>
            </button>
          </form>
        )}

        {/* Backend Target and Diagnostics */}
        <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
          <div className="flex items-center gap-1.5 truncate max-w-[220px]">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="truncate">Target: {apiBaseUrl}</span>
          </div>
          <button
            type="button"
            onClick={() => setShowConfig(!showConfig)}
            className="text-cyan-400 hover:text-cyan-300 underline font-sans flex items-center gap-1"
          >
            <Server size={11} />
            <span>{showConfig ? 'Close' : 'Change'}</span>
          </button>
        </div>

        {showConfig && (
          <div className="p-2.5 rounded-xl bg-[#030914] border border-cyan-800/50 space-y-2 text-xs">
            <label className="block text-[10px] font-mono text-slate-300">
              FASTAPI BACKEND URL
              <input
                type="url"
                value={serverUrlInput}
                onChange={(e) => setServerUrlInput(e.target.value)}
                placeholder="http://127.0.0.1:8000"
                className="mt-1 w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-xs text-white focus:border-cyan-400 focus:outline-none"
              />
            </label>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={handleSaveServerUrl}
                className="flex-1 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-[11px]"
              >
                Apply URL
              </button>
              <button
                type="button"
                onClick={() => {
                  setServerUrlInput('http://127.0.0.1:8000');
                  setApiBaseUrl('http://127.0.0.1:8000');
                  setLocalApiBaseUrl('http://127.0.0.1:8000');
                  setShowConfig(false);
                }}
                className="px-2 py-1 rounded border border-slate-700 text-slate-400 text-[11px]"
              >
                Reset Default
              </button>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
