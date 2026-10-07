import React, { useState } from 'react';
import axios from 'axios';
import { ArrowLeft, Lock, LogIn, Shield, Eye, EyeOff, User } from 'lucide-react';

import { getApiBaseUrl } from '../apiConfig';
import { loginWithGoogle, formatFirebaseAuthError } from '../firebase';

export default function Login({ onLogin, onReturnToPortal, googleAuthError }) {
  const apiBaseUrl = getApiBaseUrl();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);

  const displayedError = googleAuthError || error;

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
      setError(formatFirebaseAuthError(err));
    } finally {
      setGoogleLoading(false);
    }
  };

  const submit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(
        `${apiBaseUrl}/api/v1/auth/login`,
        { username, password },
        { timeout: 90000 },
      );
      onLogin(response.data);
    } catch (requestError) {
      if (!requestError.response) {
        setError(requestError.code === 'ECONNABORTED'
          ? `The backend at ${apiBaseUrl} did not respond in time. Check that the API is healthy and try again.`
          : `Cannot reach backend server at ${apiBaseUrl}. Check that the API is running and that its URL is correct.`);
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

  return (
    <main className="min-h-screen bg-[#030a16] text-slate-100 flex items-center justify-center p-4 sm:p-6 relative overflow-hidden">
      {/* Background ambient neon glow */}
      <div className="absolute top-1/4 -left-32 w-96 h-96 bg-cyan-500/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-1/4 -right-32 w-96 h-96 bg-emerald-500/10 rounded-full blur-[120px] pointer-events-none" />

      <div className="w-full max-w-md bg-[#081726]/90 border border-cyan-500/30 rounded-2xl p-6 sm:p-8 shadow-[0_0_50px_rgba(6,182,212,0.2)] backdrop-blur-xl space-y-4 relative z-10 animate-in fade-in zoom-in-95 duration-200">
        
        {/* Header */}
        <div className="flex items-center gap-3 border-b border-slate-800 pb-4">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Shield size={24} />
          </div>
          <div>
            <h1 className="text-xl font-black text-white tracking-wide flex items-center gap-2">
              CYBERGUARD AI
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono border border-emerald-500/30 bg-emerald-950/40 text-emerald-400 font-semibold">
                SOC v2.4
              </span>
            </h1>
            <p className="text-xs text-slate-400">Secure Operations Center Access</p>
          </div>
        </div>

        {/* Google One-Click Login */}
        <button
          type="button"
          onClick={handleGoogleSignIn}
          disabled={googleLoading || loading}
          className="w-full py-2.5 px-4 rounded-xl bg-white hover:bg-slate-100 active:bg-slate-200 text-slate-900 font-semibold text-xs sm:text-sm shadow-md transition-all flex items-center justify-center gap-2.5 cursor-pointer disabled:opacity-50 border border-slate-200"
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

        {/* Divider */}
        <div className="relative flex items-center justify-center my-2">
          <div className="border-t border-slate-700/60 w-full" />
          <span className="bg-[#081726] px-2.5 text-[10px] font-mono text-slate-400 uppercase tracking-widest shrink-0">
            or SOC credentials
          </span>
          <div className="border-t border-slate-700/60 w-full" />
        </div>

        {/* Credentials Form */}
        <form onSubmit={submit} className="space-y-3">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">Username or Email</label>
            <div className="relative">
              <input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="username or email"
                className="w-full pl-9 pr-3 py-2 bg-[#040c17] border border-slate-700 rounded-lg text-sm text-white focus:border-cyan-500 focus:outline-none transition-colors"
                required
              />
              <User size={14} className="absolute left-3 top-3 text-slate-500" />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">Password</label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Password or select demo role above"
                className="w-full pl-9 pr-9 py-2 bg-[#040c17] border border-slate-700 rounded-lg text-sm text-white focus:border-cyan-500 focus:outline-none transition-colors"
                required
              />
              <Lock size={14} className="absolute left-3 top-3 text-slate-500" />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-2.5 text-slate-400 hover:text-white transition-colors cursor-pointer p-0.5"
                title={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
          </div>

          {displayedError && (
            <p role="alert" className="text-xs text-rose-300 bg-rose-950/40 border border-rose-500/30 p-2.5 rounded-lg animate-in fade-in">
              {displayedError}
            </p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 via-cyan-500 to-blue-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 text-sm font-bold shadow-[0_0_20px_rgba(16,185,129,0.25)] hover:shadow-[0_0_25px_rgba(6,182,212,0.4)] transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
          >
            {loading ? (
              <>
                <span className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                <span>Signing in...</span>
              </>
            ) : (
              <>
                <LogIn size={15} />
                <span>Sign in to SOC</span>
              </>
            )}
          </button>

          {onReturnToPortal && (
            <button
              type="button"
              onClick={onReturnToPortal}
              className="w-full py-2 rounded-lg border border-slate-700/80 text-slate-300 hover:bg-slate-800/80 hover:text-white text-xs sm:text-sm font-medium flex items-center justify-center gap-2 transition-colors cursor-pointer"
            >
              <ArrowLeft size={14} />
              Return to portal
            </button>
          )}
        </form>
      </div>
    </main>
  );
}
