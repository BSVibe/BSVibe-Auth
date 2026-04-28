import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { hasPermission as hasPermissionImpl } from './permissions';
import { switchTenant as switchTenantImpl } from './switchTenant';
import type {
  Permission,
  SessionEnvelope,
  Tenant,
  User,
} from './types';

export interface UseAuthValue {
  user: User | null;
  tenants: Tenant[];
  activeTenant: Tenant | null;
  /** Client-side RBAC hint bound to the current `activeTenant`. */
  hasPermission: (permission: Permission) => boolean;
  /** Switch active tenant on auth-app then re-fetch session. */
  switchTenant: (tenantId: string) => Promise<void>;
  /** Re-fetch `/api/session`. */
  refresh: () => Promise<void>;
  isLoading: boolean;
  error: Error | null;
}

interface AuthProviderProps {
  /** Auth-app base URL, e.g. `https://auth.bsvibe.dev`. Trailing slashes stripped. */
  authUrl: string;
  /** Optional fetch override (for testing). */
  fetchImpl?: typeof fetch;
  children: ReactNode;
}

const AuthContext = createContext<UseAuthValue | null>(null);

/**
 * Provider that performs the silent SSO check via `/api/session` and exposes
 * the result through `useAuth()`.
 *
 * - Sends `credentials: 'include'` so the shared `.bsvibe.dev` cookies travel
 *   cross-origin from the product app to the auth app.
 * - 401 from `/api/session` is *not* an error — it just means "not logged in".
 *   `error` is reserved for transport / parse failures.
 */
export function AuthProvider({ authUrl, fetchImpl, children }: AuthProviderProps) {
  const fetcher = fetchImpl ?? (typeof fetch !== 'undefined' ? fetch : undefined);
  const baseUrl = useMemo(() => authUrl.replace(/\/+$/, ''), [authUrl]);

  const [user, setUser] = useState<User | null>(null);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [activeTenantId, setActiveTenantId] = useState<string | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  // Cancellation guard so a stale in-flight refresh doesn't overwrite newer state.
  const requestSeq = useRef(0);

  const refresh = useCallback(async () => {
    if (!fetcher) {
      setIsLoading(false);
      setError(new Error('fetch is not available in this environment'));
      return;
    }
    const seq = ++requestSeq.current;
    setIsLoading(true);
    setError(null);
    try {
      const resp = await fetcher(`${baseUrl}/api/session`, {
        method: 'GET',
        credentials: 'include',
      });

      if (seq !== requestSeq.current) return;

      if (resp.status === 401) {
        setUser(null);
        setTenants([]);
        setActiveTenantId(null);
        setAccessToken(null);
        return;
      }

      if (!resp.ok) {
        throw new Error(`session_fetch_failed: ${resp.status}`);
      }

      const data = (await resp.json()) as Partial<SessionEnvelope>;
      if (seq !== requestSeq.current) return;

      setUser(data.user ?? null);
      setTenants(Array.isArray(data.tenants) ? data.tenants : []);
      setActiveTenantId(data.active_tenant_id ?? null);
      setAccessToken(data.access_token ?? null);
    } catch (err) {
      if (seq !== requestSeq.current) return;
      setUser(null);
      setTenants([]);
      setActiveTenantId(null);
      setAccessToken(null);
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      if (seq === requestSeq.current) setIsLoading(false);
    }
  }, [baseUrl, fetcher]);

  // Initial silent SSO check.
  useEffect(() => {
    void refresh();
  }, [refresh]);

  const activeTenant = useMemo<Tenant | null>(() => {
    if (!activeTenantId) return null;
    return tenants.find((t) => t.id === activeTenantId) ?? null;
  }, [tenants, activeTenantId]);

  const switchTenant = useCallback(
    async (tenantId: string) => {
      await switchTenantImpl({
        authUrl: baseUrl,
        tenantId,
        accessToken: accessToken ?? undefined,
        fetchImpl: fetcher,
      });
      await refresh();
    },
    [baseUrl, accessToken, fetcher, refresh],
  );

  const hasPermission = useCallback(
    (permission: Permission) => hasPermissionImpl(user, activeTenant, permission),
    [user, activeTenant],
  );

  const value = useMemo<UseAuthValue>(
    () => ({
      user,
      tenants,
      activeTenant,
      hasPermission,
      switchTenant,
      refresh,
      isLoading,
      error,
    }),
    [user, tenants, activeTenant, hasPermission, switchTenant, refresh, isLoading, error],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/**
 * Read the current auth state from the nearest `<AuthProvider>`.
 *
 * Throws if used outside a provider — fail-fast keeps consumer code from
 * silently treating "no provider" as "logged out".
 */
export function useAuth(): UseAuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an <AuthProvider>');
  }
  return ctx;
}
