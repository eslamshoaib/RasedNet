import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, ApiError, setCsrfToken, UNAUTHORIZED_EVENT } from "./api";
import type { Me } from "./types";

interface AuthState {
  me: Me | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
  can: (permission: string) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  const apply = useCallback((value: Me | null) => {
    setCsrfToken(value?.csrf_token ?? null);
    setMe(value);
  }, []);

  useEffect(() => {
    api<Me>("/api/auth/me")
      .then(apply)
      .catch((e: unknown) => {
        if (!(e instanceof ApiError) || e.status !== 401) console.error(e);
        apply(null);
      })
      .finally(() => setLoading(false));
    const onUnauthorized = () => apply(null);
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, [apply]);

  const login = useCallback(
    async (username: string, password: string) => {
      apply(await api<Me>("/api/auth/login", { method: "POST", body: { username, password } }));
    },
    [apply],
  );

  const refresh = useCallback(async () => {
    apply(await api<Me>("/api/auth/me"));
  }, [apply]);

  const logout = useCallback(async () => {
    try {
      await api<void>("/api/auth/logout", { method: "POST" });
    } finally {
      apply(null);
    }
  }, [apply]);

  const can = useCallback((permission: string) => !!me?.permissions.includes(permission), [me]);

  return <AuthContext.Provider value={{ me, loading, login, logout, refresh, can }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}

/** Permission check usable anywhere (returns false outside an AuthProvider, e.g. in isolated components). */
export function useCan(): (permission: string) => boolean {
  const ctx = useContext(AuthContext);
  return (permission: string) => !!ctx?.can(permission);
}
