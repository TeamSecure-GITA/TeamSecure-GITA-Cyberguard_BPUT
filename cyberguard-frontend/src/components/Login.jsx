import React, { useState } from 'react';
import axios from 'axios';
import { LockKeyhole, LogIn, Shield, AlertTriangle } from 'lucide-react';
import { getApiBaseUrl } from '../apiConfig';
import { loginWithGoogle } from '../firebase';

export default function Login({ onLogin }) {
  const apiBaseUrl = getApiBaseUrl();
  const [username, setUsername] = useState('teamsecure.project@gmail.com');
  const [password, setPassword] = useState('Secure@9040');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/auth/login`, { username, password });
      onLogin(response.data);
    } catch (requestError) {
      if (!requestError.response) {
        setError(`Cannot reach backend server (${apiBaseUrl}). Ensure the backend is running.`);
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

  const handleGoogleSignIn = async () => {
    setGoogleLoading(true);
    setError(null);
    try {
      const session = await loginWithGoogle(apiBaseUrl);
      if (session) {
        onLogin(session);
      }
    } catch (err) {
      console.error('Google sign-in error:', err);
      if (err.code === 'auth/popup-closed-by-user') {
        setError('Google sign-in was cancelled.');
      } else if (err.code === 'auth/popup-blocked') {
        setError('Popup was blocked by your browser. Please allow popups for Google sign-in.');
      } else {
        setError(err.message || 'Failed to authenticate with Google.');
      }
    } finally {
      setGoogleLoading(false);
    }
  };

  return (
    <main className="min-h-screen min-h-[100dvh] w-full bg-[#040c17] text-slate-100 flex items-center justify-center p-3 sm:p-6 overflow-y-auto">
      <div className="w-full max-w-md bg-[#081726] border border-cyan-500/25 rounded-2xl p-5 sm:p-8 shadow-2xl shadow-cyan-950/40 space-y-5 my-auto">
        <div className="flex items-center gap-3">
          <div className="p-2.5 sm:p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Shield size={24} />
          </div>
          <div>
            <h1 className="text-lg sm:text-xl font-black text-white tracking-wide">CYBERGUARD AI</h1>
            <p className="text-xs text-slate-400">Secure SOC Operations Login</p>
          </div>
        </div>

        {/* Google One-Click Sign In */}
        <button
          type="button"
          onClick={handleGoogleSignIn}
          disabled={googleLoading || loading}
          className="w-full py-2.5 px-4 rounded-xl bg-slate-900/90 hover:bg-slate-800/90 border border-slate-700/80 hover:border-cyan-500/50 text-white text-xs sm:text-sm font-semibold flex items-center justify-center gap-3 transition-all duration-200 shadow-sm disabled:opacity-50 active:scale-[0.99]"
        >
          {/* Google G Multi-Color SVG Icon */}
          <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
            <path
              fill="#4285F4"
              d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
            />
            <path
              fill="#34A853"
              d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
            />
            <path
              fill="#FBBC05"
              d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
            />
            <path
              fill="#EA4335"
              d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
            />
          </svg>
          <span>{googleLoading ? 'Signing in with Google...' : 'Continue with Google'}</span>
        </button>

        <div className="relative flex items-center justify-center my-3">
          <div className="border-t border-slate-800 w-full" />
          <span className="bg-[#081726] px-3 text-[10px] uppercase tracking-wider font-mono text-slate-500 whitespace-nowrap">
            or continue with credentials
          </span>
          <div className="border-t border-slate-800 w-full" />
        </div>

        <form onSubmit={submit} className="space-y-4">
          <label className="block text-xs font-semibold text-slate-400">
            Username / Email
            <input
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="teamsecure.project@gmail.com"
              className="mt-1.5 w-full bg-[#040c17] border border-slate-700/80 rounded-lg p-2.5 sm:p-3 text-xs sm:text-sm text-white focus:border-cyan-500 focus:outline-none transition-colors"
            />
          </label>
          <label className="block text-xs font-semibold text-slate-400">
            Password
            <input
              autoComplete="current-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Secure@9040"
              className="mt-1.5 w-full bg-[#040c17] border border-slate-700/80 rounded-lg p-2.5 sm:p-3 text-xs sm:text-sm text-white focus:border-cyan-500 focus:outline-none transition-colors"
            />
          </label>

          {error && (
            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/30 text-xs text-rose-300 flex items-start gap-2">
              <AlertTriangle size={15} className="text-rose-400 mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading || googleLoading}
            className="w-full py-2.5 sm:py-3 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 disabled:opacity-50 text-slate-950 text-xs sm:text-sm font-bold flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(16,185,129,0.25)] transition-all"
          >
            <LockKeyhole size={16} />
            {loading ? 'Signing in...' : <><LogIn size={16} />Sign in</>}
          </button>
        </form>

        <p className="text-[11px] text-slate-400 text-center font-mono">
          Head administrator: <code className="text-cyan-300">teamsecure.project@gmail.com</code>
        </p>
      </div>
    </main>
  );
}
