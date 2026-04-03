import React, { createContext, useContext, useState, useCallback } from 'react';

const AuthContext = createContext(null);

const AUTH_BACKEND = 'http://127.0.0.1:5000';

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const stored = localStorage.getItem('sf_user');
      return stored ? JSON.parse(stored) : null;
    } catch { return null; }
  });

  const login = useCallback(async (username, password) => {
    const res = await fetch(`${AUTH_BACKEND}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (data.status === 'success') {
      const userObj = { username: data.username, role: data.role, token: data.token };
      localStorage.setItem('sf_user', JSON.stringify(userObj));
      setUser(userObj);
      return { success: true };
    }
    return { success: false, error: data.error || 'Invalid credentials' };
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('sf_user');
    setUser(null);
  }, []);

  const register = useCallback(async (username, password) => {
    const res = await fetch(`${AUTH_BACKEND}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (data.status === 'success') return { success: true };
    return { success: false, error: data.error || 'Registration failed' };
  }, []);

  const isAdmin = user?.role === 'admin';

  return (
    <AuthContext.Provider value={{ user, login, logout, register, isAdmin }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

export { AUTH_BACKEND };
