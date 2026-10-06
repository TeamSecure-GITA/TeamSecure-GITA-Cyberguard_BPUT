/**
 * Dynamic API Base URL resolver.
 * Priority order:
 * 1. User-configured override stored in localStorage ('CYBERGUARD_API_URL')
 * 2. Vite environment variable import.meta.env.VITE_API_URL
 * 3. Development-only fallback: http://127.0.0.1:8001
 */
const normalizeApiUrl = (url) => {
  const normalized = url.trim().replace(/\/+$/, '');
  const parsed = new URL(normalized);
  if (
    import.meta.env.PROD
    && (
      parsed.protocol !== 'https:'
      || parsed.hostname === 'localhost'
      || parsed.hostname === '::1'
      || /^127(?:\.\d{1,3}){3}$/.test(parsed.hostname)
    )
  ) {
    throw new Error('Production backend URLs must use public HTTPS, not a loopback host.');
  }
  return normalized;
};

export const getApiBaseUrl = () => {
  if (typeof window !== 'undefined') {
    const stored = window.localStorage.getItem('CYBERGUARD_API_URL');
    if (stored && stored.trim()) {
      return normalizeApiUrl(stored);
    }
  }
  const envUrl = import.meta.env.VITE_API_URL;
  if (envUrl && typeof envUrl === 'string' && envUrl.trim() && !envUrl.includes('your-cyberguard-backend')) {
    return normalizeApiUrl(envUrl);
  }
  if (import.meta.env.PROD) {
    throw new Error('Production backend URL is not configured. Set VITE_API_URL to the public HTTPS backend URL and redeploy.');
  }
  return 'http://127.0.0.1:8001';
};

export const setApiBaseUrl = (url) => {
  if (typeof window !== 'undefined') {
    if (!url || !url.trim() || url.trim() === 'http://127.0.0.1:8001') {
      window.localStorage.removeItem('CYBERGUARD_API_URL');
    } else {
      window.localStorage.setItem('CYBERGUARD_API_URL', normalizeApiUrl(url));
    }
  }
};
