import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  listTenantsForUser as listTenantsForUserImpl,
  pickActiveTenant,
  type SupabaseConfig,
  type Tenant,
} from "./_lib/tenants";

const COOKIE_NAME = "bsvibe_session";
const ACTIVE_TENANT_COOKIE = "bsvibe_active_tenant";
const COOKIE_MAX_AGE = 30 * 24 * 60 * 60; // 30 days
const COOKIE_DOMAIN = ".bsvibe.dev"; // shared across *.bsvibe.dev

export interface SessionHandlerDeps {
  listTenantsForUser?: (
    cfg: SupabaseConfig,
    userId: string,
    fetchImpl?: typeof fetch,
  ) => Promise<Tenant[]>;
  fetchImpl?: typeof fetch;
}

function getAllowedOrigins(): string[] {
  return (process.env.ALLOWED_REDIRECT_ORIGINS || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
}

function getCorsOrigin(req: VercelRequest): string | null {
  const origin = req.headers.origin;
  if (!origin) return null;

  const allowed = getAllowedOrigins();
  const isAllowed = allowed.some((entry) => {
    if (entry.endsWith(":*")) {
      const prefix = entry.slice(0, -2);
      return origin === prefix || origin.startsWith(prefix + ":");
    }
    return origin === entry;
  });

  return isAllowed ? origin : null;
}

function setCorsHeaders(res: VercelResponse, origin: string | null): void {
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const pair of cookieHeader.split(";")) {
    const [key, ...rest] = pair.trim().split("=");
    if (key) {
      cookies[key] = rest.join("=");
    }
  }
  return cookies;
}

interface AccessTokenPayload {
  sub?: string;
  email?: string;
  exp?: number;
}

function decodeAccessTokenPayload(token: string): AccessTokenPayload | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const padded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padLen = (4 - (padded.length % 4)) % 4;
    return JSON.parse(atob(padded + "=".repeat(padLen)));
  } catch {
    return null;
  }
}

export function createSessionHandler(deps: SessionHandlerDeps = {}) {
  const listTenants = deps.listTenantsForUser ?? listTenantsForUserImpl;
  const fetchImpl = deps.fetchImpl ?? fetch;

  return async function handler(req: VercelRequest, res: VercelResponse) {
    const corsOrigin = getCorsOrigin(req);
    setCorsHeaders(res, corsOrigin);

    if (req.method === "OPTIONS") {
      return res.status(204).end();
    }

    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!supabaseUrl || !supabaseAnonKey) {
      return res.status(500).json({ error: "Auth service not configured" });
    }

    // POST — set session cookie with refresh_token
    if (req.method === "POST") {
      const { refresh_token } = req.body ?? {};
      if (!refresh_token) {
        return res.status(400).json({ error: "refresh_token is required" });
      }

      res.setHeader(
        "Set-Cookie",
        `${COOKIE_NAME}=${refresh_token}; HttpOnly; Secure; SameSite=Lax; Domain=${COOKIE_DOMAIN}; Path=/; Max-Age=${COOKIE_MAX_AGE}`,
      );
      return res.status(200).json({ ok: true });
    }

    // GET — validate session cookie, refresh tokens, return fresh tokens + tenants
    if (req.method === "GET") {
      const cookies = parseCookies(req.headers.cookie ?? "");
      const refreshToken = cookies[COOKIE_NAME];

      if (!refreshToken) {
        return res.status(401).json({ error: "No session" });
      }

      const resp = await fetchImpl(
        `${supabaseUrl}/auth/v1/token?grant_type=refresh_token`,
        {
          method: "POST",
          headers: {
            apikey: supabaseAnonKey,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ refresh_token: refreshToken }),
        },
      );

      if (!resp.ok) {
        // Clear invalid cookie
        res.setHeader(
          "Set-Cookie",
          `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Domain=${COOKIE_DOMAIN}; Path=/; Max-Age=0`,
        );
        return res.status(401).json({ error: "Session expired" });
      }

      const data = await resp.json();

      // Best-effort tenant lookup: ignore failures so session still refreshes
      // even if the tenants table is unreachable. Recipients should treat an
      // empty tenants array as "user has no active tenants" rather than fatal.
      let tenants: Tenant[] = [];
      let activeTenantId: string | null = null;
      const payload = decodeAccessTokenPayload(data.access_token);
      const userId = payload?.sub;

      if (userId && serviceRoleKey) {
        try {
          tenants = await listTenants(
            { url: supabaseUrl, serviceRoleKey },
            userId,
            fetchImpl,
          );
          const requested = cookies[ACTIVE_TENANT_COOKIE];
          activeTenantId = pickActiveTenant(tenants, requested);
        } catch {
          tenants = [];
          activeTenantId = null;
        }
      }

      // Update cookie with new refresh token
      res.setHeader(
        "Set-Cookie",
        `${COOKIE_NAME}=${data.refresh_token}; HttpOnly; Secure; SameSite=Lax; Domain=${COOKIE_DOMAIN}; Path=/; Max-Age=${COOKIE_MAX_AGE}`,
      );

      return res.status(200).json({
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        expires_in: data.expires_in,
        tenants,
        active_tenant_id: activeTenantId,
      });
    }

    // DELETE — clear session cookie
    if (req.method === "DELETE") {
      res.setHeader(
        "Set-Cookie",
        `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Domain=${COOKIE_DOMAIN}; Path=/; Max-Age=0`,
      );
      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: "Method not allowed" });
  };
}

const defaultHandler = createSessionHandler();
export default defaultHandler;
