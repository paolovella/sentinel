// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

/**
 * Authentication provider supporting two modes:
 *
 * 1. **OIDC mode** — delegates to the server's /iam/login flow (for enterprise SSO).
 * 2. **API-key mode** — for development / single-operator deployments.
 *
 * The mode is determined by config: if OIDC issuer is set, use OIDC.
 * Otherwise fall back to API-key stored in sessionStorage.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { Role, UserSession } from "../types/api";
import * as api from "../api/client";

interface AuthState {
  authenticated: boolean;
  loading: boolean;
  session: UserSession | null;
  role: Role;
  login: () => void;
  logout: () => void;
  setApiKey: (key: string) => void;
}

const AuthContext = createContext<AuthState>({
  authenticated: false,
  loading: true,
  session: null,
  role: "viewer",
  login: () => {},
  logout: () => {},
  setApiKey: () => {},
});

export function useAuth(): AuthState {
  return useContext(AuthContext);
}

const API_KEY_STORAGE = "vellaveto_api_key";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [loading, setLoading] = useState(true);
  const [session, setSession] = useState<UserSession | null>(null);

  const checkSession = useCallback(async () => {
    try {
      const s = await api.getSession();
      setSession(s);
    } catch {
      setSession(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // On mount, configure API client from sessionStorage (if API key mode)
    const stored = sessionStorage.getItem(API_KEY_STORAGE);
    if (stored) {
      const serverUrl =
        import.meta.env.VITE_SERVER_URL ?? window.location.origin;
      api.configure(serverUrl, stored);
    }
    checkSession();
  }, [checkSession]);

  const login = useCallback(() => {
    // Redirect to server's OIDC login flow
    const serverUrl =
      import.meta.env.VITE_SERVER_URL ?? window.location.origin;
    // Use pathname (relative URL) to prevent open-redirect to external origins
    window.location.href = `${serverUrl}/iam/login?next=${encodeURIComponent(window.location.pathname)}`;
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // Ignore — server may not have session
    }
    sessionStorage.removeItem(API_KEY_STORAGE);
    setSession(null);
  }, []);

  const setApiKey = useCallback(
    (key: string) => {
      const serverUrl =
        import.meta.env.VITE_SERVER_URL ?? window.location.origin;
      sessionStorage.setItem(API_KEY_STORAGE, key);
      api.configure(serverUrl, key);
      checkSession();
    },
    [checkSession],
  );

  const value = useMemo<AuthState>(
    () => ({
      authenticated: session !== null,
      loading,
      session,
      role: session?.role ?? "viewer",
      login,
      logout,
      setApiKey,
    }),
    [session, loading, login, logout, setApiKey],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
