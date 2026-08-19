import React, { createContext, useState, useContext, useEffect, useCallback } from 'react';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [sessionExpired, setSessionExpired] = useState(false);
  const expiryTimerRef = React.useRef(null);

  const clearExpiryTimer = () => {
    if (expiryTimerRef.current) {
      clearTimeout(expiryTimerRef.current);
      expiryTimerRef.current = null;
    }
  };

  const logout = useCallback(async (expired = false) => {
    clearExpiryTimer();
    localStorage.removeItem('orca_user');
    setUser(null);
    if (expired) setSessionExpired(true);
    try {
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
    } catch { /* best-effort cookie clear */ }
  }, []);

  const scheduleExpiryLogout = useCallback((expiresAt) => {
    clearExpiryTimer();
    if (!expiresAt) return;
    const msUntilExpiry = (expiresAt * 1000) - Date.now() - (5 * 60 * 1000);
    if (msUntilExpiry <= 0) {
      logout(true);
      return;
    }
    expiryTimerRef.current = setTimeout(() => logout(true), msUntilExpiry);
  }, [logout]);

  // On mount — restore session via /auth/me (cookie sent automatically)
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch('/api/auth/me', { credentials: 'include' });
        if (res.ok) {
          const data = await res.json();
          setUser(data.user);
          localStorage.setItem('orca_user', JSON.stringify(data.user));
          scheduleExpiryLogout(data.expires_at);
        } else {
          localStorage.removeItem('orca_user');
        }
      } catch {
        localStorage.removeItem('orca_user');
      }
      setLoading(false);
    })();
  }, []);

  const login = async (username, password) => {
    setSessionExpired(false);
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('orca_user', JSON.stringify(data.user));
        setUser(data.user);
        scheduleExpiryLogout(data.expires_at);
        return { success: true };
      }

      // Non-2xx: try to read the backend's JSON error detail, but don't
      // assume the response body IS JSON -- a proxy-level failure (e.g.
      // nginx returning its own HTML 502 page) fails .json() too, and
      // that was previously unhandled right alongside the fetch() case
      // below.
      let message = `Login failed (${response.status})`;
      try {
        const error = await response.json();
        if (error.detail) message = error.detail;
      } catch {
        /* body wasn't JSON -- keep the generic status-code message */
      }
      return { success: false, message };
    } catch (err) {
      // A network-level failure (unreachable backend, DNS, TLS/cert
      // error) throws out of fetch() itself. Confirmed live 2026-08-18:
      // this was previously unhandled, so INITIALIZE_SESSION on the
      // login screen silently did nothing with zero feedback when the
      // backend was briefly unreachable (nginx caching a stale upstream
      // IP after a container restart). Always return a result object so
      // the caller's alert(result.message) has something to show instead
      // of an unhandled rejection.
      return { success: false, message: `Could not reach the server: ${err.message}` };
    }
  };

  const handle401 = useCallback(() => {
    logout(true);
  }, [logout]);

  return (
    <AuthContext.Provider value={{ user, login, logout, loading, sessionExpired, handle401 }}>
      {!loading && children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
