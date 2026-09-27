/**
 * Dynamic API Base URL resolver.
 * Priority order:
 * 1. User-configured override stored in localStorage ('CYBERGUARD_API_URL')
 * 2. Vite environment variable import.meta.env.VITE_API_URL
 * 3. Default fallback: http://127.0.0.1:8000
 */
export const getApiBaseUrl = () => {
  if (typeof window !== 'undefined') {
    const stored = window.localStorage.getItem('CYBERGUARD_API_URL');
    if (stored && stored.trim()) {
      return stored.trim().replace(/\/+$/, '');
    }
  }
  const envUrl = import.meta.env.VITE_API_URL;
  if (envUrl && typeof envUrl === 'string' && envUrl.trim() && !envUrl.includes('your-cyberguard-backend')) {
    return envUrl.trim().replace(/\/+$/, '');
  }
  return 'http://127.0.0.1:8000';
};

export const setApiBaseUrl = (url) => {
  if (typeof window !== 'undefined') {
    if (!url || !url.trim() || url.trim() === 'http://127.0.0.1:8000') {
      window.localStorage.removeItem('CYBERGUARD_API_URL');
    } else {
      window.localStorage.setItem('CYBERGUARD_API_URL', url.trim().replace(/\/+$/, ''));
    }
  }
};
