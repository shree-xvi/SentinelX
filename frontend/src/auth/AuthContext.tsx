import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api, getStoredToken, setStoredToken } from "../api/client";
import type { TokenResponse, User } from "../api/types";

interface AuthState {
  user: User | null;
  token: string | null;
  role: string | null;
  tenantId: string | null;
  isAuthenticated: boolean;
  loading: boolean;
}

interface AuthContextValue extends AuthState {
  login: (email: string, password: string) => Promise<void>;
  loginWithSso: (code: string, state: string) => Promise<void>;
  register: (payload: {
    company_name: string;
    domain: string;
    full_name: string;
    email: string;
    password: string;
  }) => Promise<void>;
  logout: () => void;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

function applySession(tokenResponse: TokenResponse): void {
  setStoredToken(tokenResponse.access_token);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(() => getStoredToken());
  const [role, setRole] = useState<string | null>(null);
  const [tenantId, setTenantId] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(() => Boolean(getStoredToken()));

  // On first load, if a token exists, resolve the current user profile.
  useEffect(() => {
    let cancelled = false;
    const stored = getStoredToken();
    if (!stored) {
      setLoading(false);
      return;
    }
    api
      .me()
      .then((profile) => {
        if (cancelled) return;
        setUser(profile);
        setRole(profile.role);
        setTenantId(profile.tenant_id);
      })
      .catch(() => {
        setStoredToken(null);
        setToken(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const tokenResponse = await api.login({ email, password });
    applySession(tokenResponse);
    setToken(tokenResponse.access_token);
    setRole(tokenResponse.role);
    setTenantId(tokenResponse.tenant_id);
    const profile = await api.me();
    setUser(profile);
  }, []);

  const register = useCallback<AuthContextValue["register"]>(async (payload) => {
    const tokenResponse = await api.register(payload);
    applySession(tokenResponse);
    setToken(tokenResponse.access_token);
    setRole(tokenResponse.role);
    setTenantId(tokenResponse.tenant_id);
    const profile = await api.me();
    setUser(profile);
  }, []);

  const loginWithSso = useCallback(async (code: string, state: string) => {
    const tokenResponse = await api.ssoCallback(code, state);
    applySession(tokenResponse);
    setToken(tokenResponse.access_token);
    setRole(tokenResponse.role);
    setTenantId(tokenResponse.tenant_id);
    const profile = await api.me();
    setUser(profile);
  }, []);

  const logout = useCallback(() => {
    setStoredToken(null);
    setToken(null);
    setUser(null);
    setRole(null);
    setTenantId(null);
  }, []);

  const refreshUser = useCallback(async () => {
    const profile = await api.me();
    setUser(profile);
    setRole(profile.role);
    setTenantId(profile.tenant_id);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      token,
      role,
      tenantId,
      isAuthenticated: Boolean(token),
      loading,
      login,
      loginWithSso,
      register,
      logout,
      refreshUser,
    }),
    [user, token, role, tenantId, loading, login, loginWithSso, register, logout, refreshUser]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}

export function isAdminRole(role: string | null): boolean {
  return role === "admin" || role === "super_admin";
}
