import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { api } from './api';
import { AuthSession } from './authSession';

const AuthContext = createContext(null);
const authSession = new AuthSession(api);

export function AuthProvider({ children }) {
  const [session, setSession] = useState(() => authSession.snapshot());
  useEffect(() => authSession.subscribe(setSession), []);
  const value = useMemo(() => ({
    ...session,
    login: (username, password) => authSession.login(username, password),
    logout: () => authSession.logout(),
    clearPermissionError: () => authSession.clearPermissionError(),
  }), [session]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used inside AuthProvider');
  return context;
}
