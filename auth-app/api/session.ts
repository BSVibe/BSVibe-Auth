import type { VercelRequest, VercelResponse } from "./_lib/types";
import {
  listTenantsForUser as listTenantsForUserImpl,
  pickActiveTenant,
  type SupabaseConfig,
  type Tenant,
} from "./_lib/tenants";
import {
  emitAuditEventBestEffort,
  type AuditEmitInput,
  type AuditEmitResult,
} from "./_lib/audit-emit";

const COOKIE_NAME = "bsvibe_session";
const ACTIVE_TENANT_COOKIE = "bsvibe_active_tenant";
const COOKIE_MAX_AGE = 30 * 24 * 60 * 60; // 30 days
const COOKIE_DOMAIN = ".bsvibe.dev"; // shared across *.bsvibe.dev

export type EmitAuditFn = (
  cfg: { url: string; serviceRoleKey: string },
  input: AuditEmitInput,
) => Promise<AuditEmitResult>;

export interface SessionHandlerDeps {
  listTenantsForUser?: (
    cfg: SupabaseConfig,
    userId: string,
    fetchImpl?: typeof fetch,
  ) => Promise<Tenant[]>;
  fetchImpl?: typeof fetch;
  emitAudit?: EmitAuditFn;
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
  const emitAudit: EmitAuditFn =
    deps.emitAudit ??
    ((cfg, input) =>
      emitAuditEventBestEffort(cfg, input, { fetchImpl }));

  return async function handler(
    req: VercelRequest,
    res: VercelResponse,
  ): Promise<VercelResponse | void> {
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

    // POST — set session cookie with refresh_token, optionally emit auth.* event
    if (req.method === "POST") {
      const postBody = (req.body ?? {}) as {
        refresh_token?: string;
        event?: string;
        email?: string;
        reason?: string;
      };

      // Failure path — no refresh_token, but we still emit auth.session.failed.
      // Tenant context is unknown for a failed login, so we use a sentinel.
      if (postBody.event === "login_failed") {
        if (serviceRoleKey) {
          // Failed-login emit uses the system actor; no tenant_id is known
          // (auth fails before the user is identified). The audit_events
          // schema requires tenant_id, so we use the all-zero UUID as a
          // sentinel that downstream queries can filter for.
          await emitAudit(
            { url: supabaseUrl, serviceRoleKey },
            {
              eventType: "auth.session.failed",
              tenantId: "00000000-0000-0000-0000-000000000000",
              actor: { type: "system", id: "auth-app" },
              data: {
                email:
                  typeof postBody.email === "string" ? postBody.email : null,
                reason:
                  typeof postBody.reason === "string"
                    ? postBody.reason
                    : "unknown",
              },
            },
          );
        }
        return res.status(204).end();
      }

      const refresh_token = postBody.refresh_token;
      if (!refresh_token) {
        return res.status(400).json({ error: "refresh_token is required" });
      }

      res.setHeader(
        "Set-Cookie",
        `${COOKIE_NAME}=${refresh_token}; HttpOnly; Secure; SameSite=Lax; Domain=${COOKIE_DOMAIN}; Path=/; Max-Age=${COOKIE_MAX_AGE}`,
      );

      // Emit auth event: signup_success -> auth.user.created,
      // login_success -> auth.session.started. Fire-and-forget; failure to
      // emit MUST NOT break the session cookie set.
      const userIdFromBody = (req.body as { user_id?: unknown } | null)?.user_id;
      if (
        (postBody.event === "signup_success" ||
          postBody.event === "login_success") &&
        typeof userIdFromBody === "string" &&
        userIdFromBody.length > 0 &&
        serviceRoleKey
      ) {
        const eventType =
          postBody.event === "signup_success"
            ? "auth.user.created"
            : "auth.session.started";
        await emitAudit(
          { url: supabaseUrl, serviceRoleKey },
          {
            eventType,
            tenantId: "00000000-0000-0000-0000-000000000000",
            actor: {
              type: "user",
              id: userIdFromBody,
              ...(typeof postBody.email === "string"
                ? { email: postBody.email }
                : {}),
            },
            data: { method: "password" },
          },
        );
      }

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
