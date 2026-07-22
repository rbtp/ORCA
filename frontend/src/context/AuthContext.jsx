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
    } else {
      const error = await response.json();
      return { success: false, message: error.detail };
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
