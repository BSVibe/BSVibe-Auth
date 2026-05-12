/**
 * Route wiring for /api/oauth/authorize.
 *
 * Composes:
 *  - resolveUser: bsvibe_session refresh-token cookie → user_id +
 *    primary tenant_id. Falls back to Authorization: Bearer for
 *    token-mode SPA clients (mirrors the /api/session GET fallback).
 *  - lookupClient: PostgREST select on oauth_clients.
 *
 * The resolveUser implementation here intentionally does NOT rotate the
 * refresh-token cookie — that's the job of /api/session GET. /oauth/authorize
 * only reads the principal; a session refresh is a side effect best left to
 * the dedicated endpoint.
 */

import type { VercelRequest, VercelResponse } from "../_lib/types";

import {
  fetchOAuthClient,
  type OAuthClientRecord,
} from "../_lib/oauth-client";
import { verifySupabaseAccessToken } from "../api-tokens/_auth";
import {
  createAuthorizeHandler,
  type AuthorizeHandlerDeps,
} from "./authorize_handler";
import type { AuthorizeEnv, OAuthClientRow } from "./authorize";

const SESSION_COOKIE = "bsvibe_session";

interface ResolveUserOptions {
  supabaseUrl: string;
  supabaseAnonKey: string;
  serviceRoleKey: string;
  fetchImpl?: typeof fetch;
}

function parseCookies(header: string | undefined): Record<string, string> {
  if (!header) return {};
  const out: Record<string, string> = {};
  for (const pair of header.split(";")) {
    const [k, ...rest] = pair.trim().split("=");
    if (k) out[k] = rest.join("=");
  }
  return out;
}

async function resolveUserIdFromCookie(
  refreshToken: string,
  opts: ResolveUserOptions,
): Promise<string | null> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const resp = await fetchImpl(
    `${opts.supabaseUrl}/auth/v1/token?grant_type=refresh_token`,
    {
      method: "POST",
      headers: {
        apikey: opts.supabaseAnonKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    },
  );
  if (!resp.ok) return null;
  const data = (await resp.json()) as { access_token?: string };
  if (typeof data.access_token !== "string") return null;
  // Decode sub claim from the access_token without verifying — Supabase
  // just minted it, so the payload is trusted within this round-trip.
  const parts = data.access_token.split(".");
  if (parts.length !== 3) return null;
  try {
    const padded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padLen = (4 - (padded.length % 4)) % 4;
    const payload = JSON.parse(atob(padded + "=".repeat(padLen))) as {
      sub?: string;
    };
    return typeof payload.sub === "string" ? payload.sub : null;
  } catch {
    return null;
  }
}

async function resolvePrimaryTenantId(
  userId: string,
  opts: ResolveUserOptions,
): Promise<string | null> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const params = new URLSearchParams({
    select: "tenant_id",
    user_id: `eq.${userId}`,
    limit: "1",
  });
  const resp = await fetchImpl(
    `${opts.supabaseUrl.replace(/\/$/, "")}/rest/v1/tenant_members?${params.toString()}`,
    {
      headers: {
        apikey: opts.serviceRoleKey,
        Authorization: `Bearer ${opts.serviceRoleKey}`,
        Accept: "application/json",
      },
    },
  );
  if (!resp.ok) return null;
  const rows = (await resp.json()) as Array<{ tenant_id?: string }>;
  return Array.isArray(rows) && rows[0]?.tenant_id ? rows[0].tenant_id : null;
}

export function createAuthorizeRouteHandler(): (
  req: VercelRequest,
  res: VercelResponse,
) => Promise<void> {
  const supabaseUrl = process.env.SUPABASE_URL ?? "";
  const supabaseAnonKey =
    process.env.SUPABASE_ANON_KEY ??
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ??
    "";
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";

  const env: AuthorizeEnv = {
    url: supabaseUrl,
    serviceRoleKey,
  };

  const deps: AuthorizeHandlerDeps = {
    resolveUser: async (req) => {
      if (!supabaseUrl || !supabaseAnonKey || !serviceRoleKey) return null;
      const opts: ResolveUserOptions = {
        supabaseUrl,
        supabaseAnonKey,
        serviceRoleKey,
      };
      const cookies = parseCookies(req.headers.cookie ?? "");
      const refresh = cookies[SESSION_COOKIE];
      let userId: string | null = null;
      if (refresh) {
        userId = await resolveUserIdFromCookie(refresh, opts);
      }
      if (!userId) {
        const auth = String(req.headers.authorization ?? "").replace(
          /^Bearer\s+/i,
          "",
        );
        if (auth) {
          userId = await verifySupabaseAccessToken(
            { url: supabaseUrl, anonKey: supabaseAnonKey },
            auth,
          );
        }
      }
      if (!userId) return null;
      const tenantId = await resolvePrimaryTenantId(userId, opts);
      return { userId, tenantId };
    },
    lookupClient: async (clientId: string): Promise<OAuthClientRow | null> => {
      if (!supabaseUrl || !serviceRoleKey) return null;
      const row: OAuthClientRecord | null = await fetchOAuthClient(
        { url: supabaseUrl, serviceRoleKey },
        clientId,
      );
      if (!row) return null;
      return {
        client_id: row.client_id,
        client_type: row.client_type,
        redirect_uris: row.redirect_uris ?? null,
        allowed_scopes: row.allowed_scopes,
        allowed_audiences: row.allowed_audiences,
        revoked_at: row.revoked_at,
      };
    },
  };

  return createAuthorizeHandler({ env, deps }) as unknown as (
    req: VercelRequest,
    res: VercelResponse,
  ) => Promise<void>;
}

export default createAuthorizeRouteHandler();
