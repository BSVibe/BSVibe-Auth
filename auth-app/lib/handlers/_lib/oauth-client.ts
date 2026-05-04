/**
 * OAuth2 client_credentials grant — credential parsing, secret hashing,
 * and Supabase row lookup.
 *
 * Hashing: PBKDF2-SHA256, 600,000 iterations, 16-byte salt, 32-byte derived
 * key. Web Crypto only (no native bindings) so the Vercel function cold-start
 * stays small. Storage format:
 *
 *   pbkdf2-sha256$<iterations>$<salt-b64url>$<hash-b64url>
 *
 * Verification is constant-time via byte-by-byte XOR comparison on the
 * decoded hash bytes.
 */

const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_SALT_BYTES = 16;
const PBKDF2_HASH_BYTES = 32;
const HASH_ALGORITHM_TAG = "pbkdf2-sha256";

export interface OAuthClientRecord {
  client_id: string;
  client_secret_hash: string;
  tenant_id: string;
  allowed_audiences: string[];
  allowed_scopes: string[];
  revoked_at: string | null;
}

export interface SupabaseConfig {
  url: string;
  serviceRoleKey: string;
}

export interface ClientCredentials {
  clientId: string;
  clientSecret: string;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (padded.length % 4)) % 4;
  const bin = atob(padded + "=".repeat(padLen));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function pbkdf2(
  plain: string,
  salt: Uint8Array,
  iterations: number,
  bytes: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(plain),
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt as unknown as ArrayBuffer,
      iterations,
      hash: "SHA-256",
    },
    key,
    bytes * 8,
  );
  return new Uint8Array(derived);
}

export async function hashClientSecret(plain: string): Promise<string> {
  if (!plain) throw new Error("client_secret must be non-empty");
  const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_BYTES));
  const hash = await pbkdf2(plain, salt, PBKDF2_ITERATIONS, PBKDF2_HASH_BYTES);
  return [
    HASH_ALGORITHM_TAG,
    PBKDF2_ITERATIONS,
    base64UrlEncode(salt),
    base64UrlEncode(hash),
  ].join("$");
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export async function verifyClientSecret(
  plain: string,
  encoded: string,
): Promise<boolean> {
  if (typeof encoded !== "string") return false;
  const parts = encoded.split("$");
  if (parts.length !== 4) return false;
  const [tag, iterStr, saltEnc, hashEnc] = parts;
  if (tag !== HASH_ALGORITHM_TAG) return false;
  const iterations = Number.parseInt(iterStr, 10);
  if (!Number.isFinite(iterations) || iterations < 1) return false;
  let salt: Uint8Array;
  let expected: Uint8Array;
  try {
    salt = base64UrlDecode(saltEnc);
    expected = base64UrlDecode(hashEnc);
  } catch {
    return false;
  }
  const computed = await pbkdf2(plain, salt, iterations, expected.length);
  return constantTimeEqual(expected, computed);
}

export function parseBasicAuthHeader(
  header: string | undefined,
): ClientCredentials | null {
  if (!header) return null;
  const m = /^Basic\s+([A-Za-z0-9+/=_-]+)\s*$/.exec(header);
  if (!m) return null;
  let decoded: string;
  try {
    decoded =
      typeof Buffer !== "undefined"
        ? Buffer.from(m[1], "base64").toString("utf8")
        : new TextDecoder().decode(base64UrlDecode(m[1].replace(/=+$/, "")));
  } catch {
    return null;
  }
  const idx = decoded.indexOf(":");
  if (idx < 0) return null;
  const clientId = decoded.slice(0, idx);
  const clientSecret = decoded.slice(idx + 1);
  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret };
}

export function parseClientCredentials(
  authorizationHeader: string | undefined,
  body: { client_id?: unknown; client_secret?: unknown },
): ClientCredentials | null {
  const fromHeader = parseBasicAuthHeader(authorizationHeader);
  if (fromHeader) return fromHeader;
  if (
    typeof body.client_id === "string" &&
    typeof body.client_secret === "string" &&
    body.client_id.length > 0 &&
    body.client_secret.length > 0
  ) {
    return { clientId: body.client_id, clientSecret: body.client_secret };
  }
  return null;
}

export async function fetchOAuthClient(
  cfg: SupabaseConfig,
  clientId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<OAuthClientRecord | null> {
  const params = new URLSearchParams({
    select:
      "client_id,client_secret_hash,tenant_id,allowed_audiences,allowed_scopes,revoked_at",
    client_id: `eq.${clientId}`,
    limit: "1",
  });
  const url = `${cfg.url.replace(/\/$/, "")}/rest/v1/oauth_clients?${params.toString()}`;
  const resp = await fetchImpl(url, {
    method: "GET",
    headers: {
      apikey: cfg.serviceRoleKey,
      Authorization: `Bearer ${cfg.serviceRoleKey}`,
      Accept: "application/json",
    },
  });
  if (!resp.ok) {
    const detail = await resp.text().catch(() => "");
    throw new Error(`oauth_clients lookup failed: ${resp.status} ${detail}`);
  }
  const rows = (await resp.json()) as OAuthClientRecord[];
  if (!Array.isArray(rows) || rows.length === 0) return null;
  return rows[0];
}

export async function touchOAuthClientLastUsed(
  cfg: SupabaseConfig,
  clientId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  const url = `${cfg.url.replace(/\/$/, "")}/rest/v1/rpc/touch_oauth_client_last_used`;
  await fetchImpl(url, {
    method: "POST",
    headers: {
      apikey: cfg.serviceRoleKey,
      Authorization: `Bearer ${cfg.serviceRoleKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ p_client_id: clientId }),
  }).catch(() => {
    // Best-effort: failure to update last_used_at must not block token mint.
  });
}
