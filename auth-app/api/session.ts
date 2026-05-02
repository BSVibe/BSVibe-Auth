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
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
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
  iat?: number;
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

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlEncodeJSON(value: unknown): string {
  return base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
}

async function hmacSha256(secret: string, message: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message),
  );
  return new Uint8Array(sig);
}

async function issueSessionJwt(input: {
  supabaseAccessToken: string;
  payload: AccessTokenPayload;
  activeTenantId: string | null;
  activeTenantRole: string | null;
}): Promise<string> {
  const signingSecret = process.env.USER_JWT_SECRET;
  if (!signingSecret || !input.payload.sub) {
    return input.supabaseAccessToken;
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = input.payload.exp ?? now + 3600;
  const iat = input.payload.iat ?? now;
  const issuer =
    process.env.USER_JWT_ISSUER ||
    `${(process.env.SUPABASE_URL || "").replace(/\/$/, "")}/auth/v1`;
  const audience = process.env.USER_JWT_AUDIENCE || "authenticated";

  const claims = {
    sub: input.payload.sub,
    email: input.payload.email,
    aud: audience,
    iss: issuer,
    exp,
    iat,
    active_tenant_id: input.activeTenantId,
    app_metadata: input.activeTenantId
      ? {
          tenant_id: input.activeTenantId,
          role: input.activeTenantRole || "member",
        }
      : {},
    user_metadata: {},
  };

  const header = { alg: "HS256", typ: "JWT" } as const;
  const signingInput = `${base64UrlEncodeJSON(header)}.${base64UrlEncodeJSON(claims)}`;
  const signature = await hmacSha256(signingSecret, signingInput);
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

async function buildSessionFromRefreshToken(
  refreshToken: string,
  options: {
    supabaseUrl: string;
    supabaseAnonKey: string;
    serviceRoleKey?: string;
    requestedTenantId?: string;
    fetchImpl: typeof fetch;
    listTenants: NonNullable<SessionHandlerDeps["listTenantsForUser"]>;
  },
) {
  const resp = await options.fetchImpl(
    `${options.supabaseUrl}/auth/v1/token?grant_type=refresh_token`,
    {
      method: "POST",
      headers: {
        apikey: options.supabaseAnonKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    },
  );

  if (!resp.ok) {
    return null;
  }

  const data = await resp.json();
  let tenants: Tenant[] = [];
  let activeTenantId: string | null = null;
  const payload = decodeAccessTokenPayload(data.access_token);
  const userId = payload?.sub;

  if (userId && options.serviceRoleKey) {
    try {
      tenants = await options.listTenants(
        { url: options.supabaseUrl, serviceRoleKey: options.serviceRoleKey },
        userId,
        options.fetchImpl,
      );
      activeTenantId = pickActiveTenant(tenants, options.requestedTenantId);
    } catch {
      tenants = [];
      activeTenantId = null;
    }
  }

  const activeTenantRole =
    tenants.find((tenant) => tenant.id === activeTenantId)?.role ?? null;
  const accessToken = await issueSessionJwt({
    supabaseAccessToken: data.access_token,
    payload: payload ?? {},
    activeTenantId,
    activeTenantRole,
  });

  return {
    access_token: accessToken,
    refresh_token: data.refresh_token,
    expires_in: data.expires_in,
    tenants,
    active_tenant_id: activeTenantId,
  };
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

      const session = await buildSessionFromRefreshToken(refresh_token, {
        supabaseUrl,
        supabaseAnonKey,
        serviceRoleKey,
        fetchImpl,
        listTenants,
      });

      if (!session) {
        res.setHeader(
          "Set-Cookie",
          `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Domain=${COOKIE_DOMAIN}; Path=/; Max-Age=0`,
        );
        return res.status(401).json({ error: "Session expired" });
      }

      res.setHeader(
        "Set-Cookie",
        `${COOKIE_NAME}=${session.refresh_token}; HttpOnly; Secure; SameSite=Lax; Domain=${COOKIE_DOMAIN}; Path=/; Max-Age=${COOKIE_MAX_AGE}`,
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

      return res.status(200).json(session);
    }

    // GET — validate session cookie, refresh tokens, return fresh tokens + tenants.
    // Bearer fallback: token-mode clients (e2e, localStorage SPAs without
    // cross-subdomain cookies) can send the Supabase access_token via
    // `Authorization: Bearer …`. Auth-app validates it against
    // Supabase /auth/v1/user, looks up the caller's tenants list, and
    // returns the same shape — minus a fresh refresh_token, which only
    // the cookie flow rotates.
    if (req.method === "GET") {
      const cookies = parseCookies(req.headers.cookie ?? "");
      const refreshToken = cookies[COOKIE_NAME];

      if (!refreshToken) {
        const bearer = (req.headers.authorization ?? "")
          .replace(/^Bearer\s+/i, "")
          .trim();
        if (!bearer) {
          return res.status(401).json({ error: "No session" });
        }
        const userResp = await fetchImpl(`${supabaseUrl}/auth/v1/user`, {
          headers: {
            apikey: supabaseAnonKey,
            Authorization: `Bearer ${bearer}`,
          },
        });
        if (!userResp.ok) {
          return res.status(401).json({ error: "Invalid bearer token" });
        }
        const userBody = (await userResp.json()) as { id?: string };
        const userId = userBody?.id;
        if (!userId) {
          return res.status(401).json({ error: "Invalid bearer token" });
        }
        let tenants: Tenant[] = [];
        if (serviceRoleKey) {
          try {
            tenants = await listTenants(
              { url: supabaseUrl, serviceRoleKey },
              userId,
              fetchImpl,
            );
          } catch {
            tenants = [];
          }
        }
        const activeTenantId = pickActiveTenant(tenants, undefined);
        const payload = decodeAccessTokenPayload(bearer);
        const expiresIn = payload?.exp
          ? Math.max(1, payload.exp - Math.floor(Date.now() / 1000))
          : 3600;
        return res.status(200).json({
          access_token: bearer,
          refresh_token: "",
          expires_in: expiresIn,
          tenants,
          active_tenant_id: activeTenantId,
        });
      }

      const session = await buildSessionFromRefreshToken(refreshToken, {
        supabaseUrl,
        supabaseAnonKey,
        serviceRoleKey,
        requestedTenantId: cookies[ACTIVE_TENANT_COOKIE],
        fetchImpl,
        listTenants,
      });

      if (!session) {
        // Clear invalid cookie
        res.setHeader(
          "Set-Cookie",
          `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Domain=${COOKIE_DOMAIN}; Path=/; Max-Age=0`,
        );
        return res.status(401).json({ error: "Session expired" });
      }

      // Update cookie with new refresh token
      res.setHeader(
        "Set-Cookie",
        `${COOKIE_NAME}=${session.refresh_token}; HttpOnly; Secure; SameSite=Lax; Domain=${COOKIE_DOMAIN}; Path=/; Max-Age=${COOKIE_MAX_AGE}`,
      );

      return res.status(200).json(session);
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
