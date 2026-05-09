/**
 * Shared user-auth helpers for /api/tokens handlers.
 *
 * Mirrors the pattern in service-tokens/issue.ts: a Bearer Supabase
 * access_token is verified against `/auth/v1/user`, returning the user_id.
 * Each handler injects this via deps so tests can stub it.
 */

import type { VercelRequest, VercelResponse } from "../_lib/types";

export type VerifyAccessTokenFn = (
  cfg: { url: string; anonKey: string },
  accessToken: string,
  fetchImpl?: typeof fetch,
) => Promise<string | null>;

export async function verifySupabaseAccessToken(
  cfg: { url: string; anonKey: string },
  accessToken: string,
  fetchImpl: typeof fetch = fetch,
): Promise<string | null> {
  const resp = await fetchImpl(`${cfg.url}/auth/v1/user`, {
    method: "GET",
    headers: {
      apikey: cfg.anonKey,
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });
  if (resp.ok) {
    const user = (await resp.json()) as { id?: string };
    if (typeof user.id === "string" && user.id.length > 0) return user.id;
  }
  // Fallback: the auth-app /api/session GET wraps the raw Supabase access
  // token in a session JWT (HS256, signed with USER_JWT_SECRET, carries
  // active_tenant_id + role). Subdomain consumers (bsvibe-site /account
  // /tokens proxy etc.) hold *that* JWT, not the raw Supabase one — verify
  // it locally so they aren't forced to re-fetch the raw token.
  return await verifySessionJwt(accessToken);
}

async function verifySessionJwt(token: string): Promise<string | null> {
  const secret = process.env.USER_JWT_SECRET;
  if (!secret) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;
  let header: { alg?: string; typ?: string };
  let payload: { sub?: string; exp?: number };
  try {
    header = JSON.parse(base64UrlDecodeString(headerB64));
    payload = JSON.parse(base64UrlDecodeString(payloadB64));
  } catch {
    return null;
  }
  if (header.alg !== "HS256") return null;
  if (typeof payload.exp === "number" && payload.exp * 1000 < Date.now()) {
    return null;
  }
  const expected = await hmacSha256(secret, `${headerB64}.${payloadB64}`);
  const provided = base64UrlDecodeBytes(sigB64);
  if (!constantTimeEqual(expected, provided)) return null;
  return typeof payload.sub === "string" && payload.sub.length > 0
    ? payload.sub
    : null;
}

function base64UrlDecodeString(s: string): string {
  return new TextDecoder().decode(base64UrlDecodeBytes(s));
}

function base64UrlDecodeBytes(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (padded.length % 4)) % 4;
  const bin = atob(padded + "=".repeat(padLen));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
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

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export interface ResolvedEnv {
  supabaseUrl: string;
  supabaseAnonKey: string;
  serviceRoleKey: string;
}

export function readEnv(): ResolvedEnv | null {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseAnonKey =
    process.env.SUPABASE_ANON_KEY ?? process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !supabaseAnonKey || !serviceRoleKey) return null;
  return { supabaseUrl, supabaseAnonKey, serviceRoleKey };
}

/**
 * Strict UUID v4-ish check — accepts the canonical 8-4-4-4-12 hex form.
 * The DB column is uuid; non-uuid input would 500 the PostgREST call.
 */
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

/** Metadata columns safe to expose to the user — never includes hashes. */
export const METADATA_SELECT =
  "id,type,prefix,name,audience,scopes,created_at,expires_at,last_used_at,revoked_at";

/**
 * Handle OPTIONS preflight + non-matching method. Returns true when the
 * response was already sent (caller bails); false to continue.
 */
export function handleCorsAndMethod(
  req: VercelRequest,
  res: VercelResponse,
  method: "GET" | "POST" | "DELETE" | "PATCH",
): boolean {
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", `${method}, OPTIONS`);
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.status(204).end();
    return true;
  }
  if (req.method !== method) {
    res.status(405).json({ error: "Method not allowed" });
    return true;
  }
  return false;
}

/** Standard service-role headers for Supabase REST calls. */
export function supabaseServiceHeaders(env: { serviceRoleKey: string }) {
  return {
    apikey: env.serviceRoleKey,
    Authorization: `Bearer ${env.serviceRoleKey}`,
    Accept: "application/json",
  } as const;
}

/**
 * Resolve `:id` from either `req.query.id` (set by Vercel-style routing or test
 * shims) or — for Next.js App Router dynamic segments — by parsing it out of
 * `/api/tokens/<id>` in `req.url`. Returns `undefined` if neither yields a value.
 */
export function getTokenIdFromRequest(req: VercelRequest): string | undefined {
  const fromQuery = req.query?.id;
  if (typeof fromQuery === "string" && fromQuery.length > 0) return fromQuery;
  const url = (req as { url?: string }).url ?? "";
  const m = /\/tokens\/([^/?#]+)/.exec(url);
  return m ? decodeURIComponent(m[1]) : undefined;
}

export async function authenticate(
  req: VercelRequest,
  res: VercelResponse,
  verifyAccessToken: VerifyAccessTokenFn,
  fetchImpl: typeof fetch,
): Promise<{ userId: string; env: ResolvedEnv } | null> {
  const env = readEnv();
  if (!env) {
    res.status(500).json({ error: "Auth service not configured" });
    return null;
  }
  const accessToken = (req.headers.authorization ?? "")
    .replace(/^Bearer\s+/i, "")
    .trim();
  if (!accessToken) {
    res.status(401).json({ error: "Not authenticated" });
    return null;
  }
  const userId = await verifyAccessToken(
    { url: env.supabaseUrl, anonKey: env.supabaseAnonKey },
    accessToken,
    fetchImpl,
  );
  if (!userId) {
    res.status(401).json({ error: "Invalid access_token" });
    return null;
  }
  return { userId, env };
}
