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
  if (!resp.ok) return null;
  const user = (await resp.json()) as { id?: string };
  return typeof user.id === "string" && user.id.length > 0 ? user.id : null;
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
