/**
 * Shared helpers for the /api/oauth/clients surface (Round 5 service-account UI).
 *
 * Service accounts are confidential oauth_clients with a tenant binding
 * and a PBKDF2-hashed secret. Created via this user-authenticated
 * surface so dashboard users can mint CI/CD credentials without going
 * through ops.
 */

import type { VercelRequest } from "../_lib/types";

const AUDIENCES = new Set([
  "gateway",
  "sage",
  "nexus",
  "supervisor",
  "bsvibe-auth",
]);

/** RFC 9728-aligned scope grammar — `audience:resource` (':*' allowed). */
const SCOPE_PATTERN = /^[a-z][a-z0-9-]*:(?:\*|[a-z][a-z0-9-]*(?:[._-][a-z0-9]+)*)$/;

export function isAllowedAudience(value: unknown): value is string {
  return typeof value === "string" && AUDIENCES.has(value);
}

export function isValidScope(value: unknown): value is string {
  return typeof value === "string" && SCOPE_PATTERN.test(value);
}

/** ``svc-<16-hex>`` — matches the oauth_clients client_id regex
 *  (`^[a-z][a-z0-9_-]{2,63}$`). */
export function generateClientId(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return `svc-${hex}`;
}

/** base62 URL-safe random ~43-char secret. Strong enough for a
 *  ``client_credentials`` shared secret; PBKDF2-hashed at rest. */
export function generateClientSecret(): string {
  const ALPH =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += ALPH[b % 62];
  return out;
}

export async function resolvePrimaryTenantId(
  fetchImpl: typeof fetch,
  supabaseUrl: string,
  serviceRoleKey: string,
  userId: string,
): Promise<string | null> {
  const params = new URLSearchParams({
    select: "tenant_id",
    user_id: `eq.${userId}`,
    limit: "1",
  });
  const resp = await fetchImpl(
    `${supabaseUrl.replace(/\/$/, "")}/rest/v1/tenant_members?${params.toString()}`,
    {
      headers: {
        apikey: serviceRoleKey,
        Authorization: `Bearer ${serviceRoleKey}`,
        Accept: "application/json",
      },
    },
  );
  if (!resp.ok) return null;
  const rows = (await resp.json()) as Array<{ tenant_id?: string }>;
  return Array.isArray(rows) && rows[0]?.tenant_id ? rows[0].tenant_id : null;
}

export function getClientIdFromRequest(req: VercelRequest): string | undefined {
  const fromQuery = req.query?.id;
  if (typeof fromQuery === "string" && fromQuery.length > 0) return fromQuery;
  const url = (req as { url?: string }).url ?? "";
  const m = /\/oauth\/clients\/([^/?#]+)/.exec(url);
  return m ? decodeURIComponent(m[1]) : undefined;
}

/** Columns safe to expose to the user — never includes client_secret_hash. */
export const OAUTH_CLIENT_METADATA_SELECT =
  "client_id,description,client_type,tenant_id,allowed_audiences,allowed_scopes,created_at,revoked_at,last_used_at";

export const CLIENT_ID_PATTERN = /^svc-[0-9a-f]{16}$/;
