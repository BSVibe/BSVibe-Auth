import type { SwitchTenantResponse } from './types';

export interface SwitchTenantOptions {
  /** Auth-app base URL, e.g. `https://auth.bsvibe.dev`. Trailing slashes are stripped. */
  authUrl: string;
  /** Tenant to switch to. Must be one the user is a member of. */
  tenantId: string;
  /** Optional access token. When supplied, sent as `Authorization: Bearer <token>`. */
  accessToken?: string;
  /** Optional fetch override (for testing). Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

/**
 * POST `/api/session/switch_tenant` and return the auth-app's response.
 *
 * Always sends `credentials: 'include'` so the shared `bsvibe_*` cookies are
 * forwarded to `auth.bsvibe.dev` (the only origin authoritative for the
 * active-tenant cookie).
 *
 * On non-2xx, throws an Error whose `.message` is the server's `error` string
 * (or a generic `switch_tenant_failed` if the body is malformed).
 */
export async function switchTenant(
  opts: SwitchTenantOptions,
): Promise<SwitchTenantResponse> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const base = opts.authUrl.replace(/\/+$/, '');
  const url = `${base}/api/session/switch_tenant`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (opts.accessToken) {
    headers.Authorization = `Bearer ${opts.accessToken}`;
  }

  const resp = await fetchImpl(url, {
    method: 'POST',
    credentials: 'include',
    headers,
    body: JSON.stringify({ tenant_id: opts.tenantId }),
  });

  if (!resp.ok) {
    let message = 'switch_tenant_failed';
    try {
      const body = (await resp.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      /* keep default */
    }
    throw new Error(message);
  }

  return (await resp.json()) as SwitchTenantResponse;
}
