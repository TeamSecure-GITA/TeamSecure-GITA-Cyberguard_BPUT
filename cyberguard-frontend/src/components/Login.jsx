import React, { useState } from 'react';
import axios from 'axios';
import { LockKeyhole, LogIn, Shield } from 'lucide-react';

const apiBaseUrl = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('lead');
  const [password, setPassword] = useState('lead123');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await axios.post(`${apiBaseUrl}/api/v1/auth/login`, { username, password });
      onLogin(response.data);
    } catch (requestError) {
      if (requestError.response?.data?.detail) {
        setError(requestError.response.data.detail);
      } else if (requestError.request) {
        setError('Backend unavailable. Start FastAPI on port 8000.');
      } else {
        setError('Unable to send the login request.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-darkBg text-slate-100 flex items-center justify-center p-6">
      <form onSubmit={submit} className="w-full max-w-md bg-cardBg border border-slate-700 rounded-2xl p-8 shadow-2xl space-y-5">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400"><Shield size={26} /></div>
          <div><h1 className="text-xl font-black text-white">CYBERGUARD</h1><p className="text-xs text-slate-400">Secure SOC access</p></div>
        </div>
        <label className="block text-xs font-semibold text-slate-400">Username
          <input value={username} onChange={(event) => setUsername(event.target.value)} className="mt-2 w-full bg-darkBg border border-slate-700 rounded-lg p-3 text-sm text-white focus:border-cyan-500 focus:outline-none" />
        </label>
        <label className="block text-xs font-semibold text-slate-400">Password
          <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} className="mt-2 w-full bg-darkBg border border-slate-700 rounded-lg p-3 text-sm text-white focus:border-cyan-500 focus:outline-none" />
        </label>
        {error && <p className="text-xs text-red-400">{error}</p>}
        <button disabled={loading} className="w-full py-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-sm font-semibold flex items-center justify-center gap-2"><LockKeyhole size={16} />{loading ? 'Signing in...' : <><LogIn size={16} />Sign in</>}</button>
        <p className="text-[11px] text-slate-500">Demo accounts: analyst / analyst123, lead / lead123</p>
      </form>
    </main>
  );
}
