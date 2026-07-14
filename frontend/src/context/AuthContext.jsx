import React, { createContext, useState, useContext, useEffect, useCallback } from 'react';

const AuthContext = createContext(null);

const TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000; // re-login 5 min before expiry

function getTokenExpiry(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.exp ? payload.exp * 1000 : null; // convert to ms
  } catch {
    return null;
  }
}

function isTokenExpired(token) {
  const exp = getTokenExpiry(token);
  if (!exp) return true;
  return Date.now() >= exp;
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [sessionExpired, setSessionExpired] = useState(false);

  const logout = useCallback((expired = false) => {
    localStorage.removeItem('orca_token');
    localStorage.removeItem('orca_user');
    setUser(null);
    if (expired) setSessionExpired(true);
  }, []);

  // On mount — check token validity before restoring session
  useEffect(() => {
    const savedUser = localStorage.getItem('orca_user');
    const token = localStorage.getItem('orca_token');
    if (savedUser && token) {
      if (isTokenExpired(token)) {
        logout(true);
      } else {
        setUser(JSON.parse(savedUser));
        scheduleExpiryLogout(token);
      }
    }
    setLoading(false);
  }, []);

  // Schedule auto-logout before token expires so it's graceful, not a 401
  const scheduleExpiryLogout = useCallback((token) => {
    const exp = getTokenExpiry(token);
    if (!exp) return;
    const msUntilWarning = exp - Date.now() - TOKEN_REFRESH_MARGIN_MS;
    if (msUntilWarning <= 0) {
      logout(true);
      return;
    }
    const timer = setTimeout(() => logout(true), msUntilWarning);
    return () => clearTimeout(timer);
  }, [logout]);

  const login = async (username, password) => {
    setSessionExpired(false);
    const response = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    if (response.ok) {
      const data = await response.json();
      localStorage.setItem('orca_token', data.access_token);
      localStorage.setItem('orca_user', JSON.stringify(data.user));
      setUser(data.user);
      scheduleExpiryLogout(data.access_token);
      return { success: true };
    } else {
      const error = await response.json();
      return { success: false, message: error.detail };
    }
  };

  // Global 401 interceptor — any fetch that gets a 401 triggers graceful session expiry
  // Components can call this instead of rolling their own logout-on-401 logic
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
