/**
 * OAuth 2.0 authorization_code grant helpers (RFC 6749 §4.1, RFC 7636 PKCE).
 *
 * Two pieces:
 *
 * 1. ``issueAuthorizationCode`` — called by ``/oauth/authorize`` after the
 *    user is authenticated + has consented. Persists a single-use code
 *    bound to the client + redirect_uri + PKCE challenge, returns the
 *    raw code for the redirect.
 *
 * 2. ``claimAuthorizationCode`` — called by ``/oauth/token`` under the
 *    ``authorization_code`` grant. Atomically flips the row to
 *    ``used_at = now`` and verifies the supplied ``code_verifier``
 *    against the stored ``code_challenge`` (S256 only). On a second
 *    claim the row is already consumed → ``invalid_grant``.
 *
 * Storage shape lives in supabase migration ``20260512_000001`` —
 * ``oauth_codes`` table.
 */

import { createHash, randomBytes } from "node:crypto";

const CODE_TTL_S = 10 * 60; // 10 minutes (RFC 6749 §4.1.2 recommendation)
const CODE_BYTES = 32; // 256 bits of random; base64url-encoded → 43 chars

export interface IssueAuthorizationCodeEnv {
  url: string;
  serviceRoleKey: string;
}

export interface IssueAuthorizationCodeInput {
  clientId: string;
  userId: string;
  tenantId: string | null;
  scope: string[];
  audience: string[];
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
}

export interface IssueAuthorizationCodeOptions {
  fetchImpl?: typeof fetch;
  now?: () => number;
  randomCode?: () => string;
}

export async function issueAuthorizationCode(
  env: IssueAuthorizationCodeEnv,
  input: IssueAuthorizationCodeInput,
  options: IssueAuthorizationCodeOptions = {},
): Promise<{ code: string; expiresAt: string }> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;
  const code = (options.randomCode ?? defaultRandomCode)();
  const expiresAt = new Date(now() + CODE_TTL_S * 1000).toISOString();

  const url = new URL(`${env.url}/rest/v1/oauth_codes`);
  const headers = {
    apikey: env.serviceRoleKey,
    Authorization: `Bearer ${env.serviceRoleKey}`,
    "Content-Type": "application/json",
    Accept: "application/json",
    Prefer: "return=minimal",
  } as const;

  const body = {
    code,
    client_id: input.clientId,
    user_id: input.userId,
    tenant_id: input.tenantId,
    scope: input.scope,
    audience: input.audience,
    redirect_uri: input.redirectUri,
    code_challenge: input.codeChallenge,
    code_challenge_method: input.codeChallengeMethod,
    expires_at: expiresAt,
  };

  const resp = await fetchImpl(url.toString(), {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    throw new AuthorizationCodeStoreError(
      `failed to persist authorization code (status=${resp.status})`,
    );
  }
  return { code, expiresAt };
}

export class AuthorizationCodeStoreError extends Error {}

export type ClaimAuthorizationCodeOutcome =
  | {
      kind: "claimed";
      clientId: string;
      userId: string;
      tenantId: string | null;
      scope: string[];
      audience: string[];
      redirectUri: string;
    }
  | { kind: "not_found" }
  | { kind: "used" }
  | { kind: "expired" }
  | { kind: "client_mismatch" }
  | { kind: "redirect_uri_mismatch" }
  | { kind: "pkce_mismatch" };

export interface ClaimAuthorizationCodeInput {
  code: string;
  expectedClientId: string;
  redirectUri: string;
  codeVerifier: string;
}

export async function claimAuthorizationCode(
  env: IssueAuthorizationCodeEnv,
  input: ClaimAuthorizationCodeInput,
  options: { fetchImpl?: typeof fetch; now?: () => number } = {},
): Promise<ClaimAuthorizationCodeOutcome> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;
  const nowIso = new Date(now()).toISOString();

  const headers = {
    apikey: env.serviceRoleKey,
    Authorization: `Bearer ${env.serviceRoleKey}`,
    Accept: "application/json",
  } as const;

  // 1) Atomic claim: row must be unused + non-expired.
  const claimUrl = new URL(`${env.url}/rest/v1/oauth_codes`);
  claimUrl.searchParams.set("code", `eq.${input.code}`);
  claimUrl.searchParams.set("used_at", "is.null");
  claimUrl.searchParams.set("expires_at", `gt.${nowIso}`);

  const claimResp = await fetchImpl(claimUrl.toString(), {
    method: "PATCH",
    headers: { ...headers, "Content-Type": "application/json", Prefer: "return=representation" },
    body: JSON.stringify({ used_at: nowIso }),
  });
  if (!claimResp.ok) {
    return { kind: "not_found" };
  }
  const claimed = (await claimResp.json()) as Array<{
    code: string;
    client_id: string;
    user_id: string;
    tenant_id: string | null;
    scope: unknown;
    audience: unknown;
    redirect_uri: string;
    code_challenge: string;
    code_challenge_method: string;
  }>;

  if (!Array.isArray(claimed) || claimed.length === 0) {
    // 2) Diagnostic — row exists in some other state?
    const lookupUrl = new URL(`${env.url}/rest/v1/oauth_codes`);
    lookupUrl.searchParams.set("select", "code,used_at,expires_at");
    lookupUrl.searchParams.set("code", `eq.${input.code}`);
    lookupUrl.searchParams.set("limit", "1");
    const lookupResp = await fetchImpl(lookupUrl.toString(), { headers });
    if (!lookupResp.ok) return { kind: "not_found" };
    const rows = (await lookupResp.json()) as Array<{
      used_at: string | null;
      expires_at: string;
    }>;
    if (!Array.isArray(rows) || rows.length === 0) return { kind: "not_found" };
    const row = rows[0];
    if (row.used_at !== null) return { kind: "used" };
    if (new Date(row.expires_at).getTime() < now()) return { kind: "expired" };
    return { kind: "not_found" };
  }

  const row = claimed[0];

  // 3) Cross-checks — these MUST come after the atomic claim. The row is
  //    already consumed (single-use) regardless of whether the verifier
  //    matches; a mismatch here means an attacker is trying to redeem a
  //    code they intercepted but can't supply the verifier for.
  if (row.client_id !== input.expectedClientId) return { kind: "client_mismatch" };
  if (!redirectUrisMatch(row.redirect_uri, input.redirectUri)) {
    return { kind: "redirect_uri_mismatch" };
  }
  if (!verifyPkce(row.code_challenge, row.code_challenge_method, input.codeVerifier)) {
    return { kind: "pkce_mismatch" };
  }

  return {
    kind: "claimed",
    clientId: row.client_id,
    userId: row.user_id,
    tenantId: row.tenant_id,
    scope: asStringArray(row.scope),
    audience: asStringArray(row.audience),
    redirectUri: row.redirect_uri,
  };
}

function asStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string");
}

function defaultRandomCode(): string {
  return base64UrlEncode(randomBytes(CODE_BYTES));
}

function base64UrlEncode(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

/**
 * Compare the stored `redirect_uri` against the value supplied on the
 * token-exchange leg. Per RFC 8252 §7.3, loopback hostnames
 * (`127.0.0.1`, `localhost`, `[::1]`) refer to the same endpoint and
 * MUST be treated as interchangeable. Non-loopback URIs require strict
 * string equality.
 *
 * Background. The auth-app surfaces `127.0.0.1` requests as
 * `localhost` once the request makes a round-trip through the
 * /oauth/authorize → /login bounce — the precise normalization point
 * is in the upstream URL parser (Next.js / Vercel edge), not in our
 * code, but the observable behavior is the same. Strict equality
 * burns the code with `redirect_uri_mismatch`, blocking every CLI
 * client that hard-codes `127.0.0.1` (bsvibe-cli-base 0.2.0+
 * loopback listener).
 */
export function redirectUrisMatch(stored: string, supplied: string): boolean {
  if (stored === supplied) return true;
  let s: URL;
  let r: URL;
  try {
    s = new URL(stored);
    r = new URL(supplied);
  } catch {
    return false;
  }
  if (s.protocol !== r.protocol) return false;
  if (s.pathname !== r.pathname) return false;
  if (s.search !== r.search) return false;
  if (s.port !== r.port) return false;
  if (!LOOPBACK_HOSTS.has(s.hostname) || !LOOPBACK_HOSTS.has(r.hostname)) {
    return false;
  }
  return true;
}

/**
 * Verify a PKCE code_verifier matches the previously-stored
 * code_challenge (RFC 7636 §4.6). S256 only — we never accept ``plain``
 * since every supported client (CLI, Claude Code, IDE plugins) supports
 * SHA-256.
 */
export function verifyPkce(
  challenge: string,
  method: string,
  verifier: string,
): boolean {
  if (method !== "S256") return false;
  if (!isValidVerifier(verifier)) return false;
  const computed = base64UrlEncode(createHash("sha256").update(verifier).digest());
  // Constant-time-ish comparison — verifier strings are short and the
  // attacker has no oracle that depends on early-exit timing.
  if (computed.length !== challenge.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) {
    diff |= computed.charCodeAt(i) ^ challenge.charCodeAt(i);
  }
  return diff === 0;
}

function isValidVerifier(v: string): boolean {
  // RFC 7636 §4.1: code_verifier = high-entropy cryptographic random
  // STRING, [A-Z]/[a-z]/[0-9]/-._~, 43-128 chars.
  if (v.length < 43 || v.length > 128) return false;
  return /^[A-Za-z0-9\-._~]+$/.test(v);
}

export const __test_only__ = { CODE_TTL_S, isValidVerifier };
