/**
 * Token primitives for personal access tokens (PATs) and refresh tokens.
 *
 * - PAT JWTs: HS256 signed with the same secret as service tokens. Distinct
 *   `token_type: "pat"` claim distinguishes them from service-to-service JWTs.
 * - Refresh tokens: 32-byte urlsafe base64 random; stored as sha256(raw).
 *
 * (The legacy ``bsv_sk_*`` / ``bsv_pk_*`` opaque API-key primitives were
 * retired in Tier 2 of the 2026-05 auth cleanup — the issuance entry point
 * died in Tier 1, the prefix dispatch died in bsvibe-authz 1.3.0, and the
 * ``tokens.prefix`` / ``tokens.token_hash`` columns are dropped by the
 * migration shipped with this PR.)
 *
 * Web Crypto only — no jose / jsonwebtoken dependency.
 */

import { base64UrlEncode, base64UrlEncodeJSON, hmacSha256 } from "./jwt-crypto";

const REFRESH_RANDOM_BYTES = 32;

export interface RefreshToken {
  raw: string;
  hash: Uint8Array;
}

export interface PatJwtInput {
  sub: string;
  tenant: string;
  aud: string[];
  scope: string[];
  jti: string;
  /** When omitted, the JWT is minted without an `exp` claim (never-expiring PAT).
   *  Server-side revoke + DB `expires_at IS NULL` check is the only safety net. */
  exp?: number;
  iat?: number;
}

export interface PatJwtPayload {
  iss: string;
  sub: string;
  tenant: string;
  aud: string[];
  scope: string[];
  jti: string;
  iat: number;
  exp?: number;
  token_type: "pat";
}

export interface PatJwtConfig {
  signingSecret: string;
  issuer: string;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex string must have even length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at offset ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

const textEncoder = new TextEncoder();

export async function sha256Bytes(input: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(input));
  return new Uint8Array(digest);
}

/**
 * Generate a single-use refresh token. Returns the raw value (sent to the
 * client once) and sha256(raw) for storage in `refresh_tokens.hash`.
 */
export async function generateRefreshToken(): Promise<RefreshToken> {
  const random = crypto.getRandomValues(new Uint8Array(REFRESH_RANDOM_BYTES));
  const raw = base64UrlEncode(random);
  const hash = await sha256Bytes(raw);
  return { raw, hash };
}

/**
 * Sign an HS256 PAT JWT. Mirrors the structure of service-token.ts but uses
 * `token_type: "pat"` and carries `tenant` + `aud[]` + `scope[]` claims tied
 * to a row in `tokens` (jti).
 */
export async function generatePatJwt(
  input: PatJwtInput,
  cfg: PatJwtConfig,
): Promise<string> {
  if (!cfg.signingSecret) {
    throw new Error("missing_secret: PAT signing secret not configured");
  }
  const iat = input.iat ?? Math.floor(Date.now() / 1000);
  const payload: PatJwtPayload = {
    iss: cfg.issuer,
    sub: input.sub,
    tenant: input.tenant,
    aud: input.aud,
    scope: input.scope,
    jti: input.jti,
    iat,
    token_type: "pat",
    ...(typeof input.exp === "number" ? { exp: input.exp } : {}),
  };
  const header = { alg: "HS256", typ: "JWT" } as const;
  const headerEnc = base64UrlEncodeJSON(header);
  const payloadEnc = base64UrlEncodeJSON(payload);
  const signingInput = `${headerEnc}.${payloadEnc}`;
  const signature = await hmacSha256(cfg.signingSecret, signingInput);
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

export function decodePatJwtPayload<T = PatJwtPayload>(token: string): T {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid_jwt");
  const padded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (padded.length % 4)) % 4;
  return JSON.parse(atob(padded + "=".repeat(padLen))) as T;
}

export async function verifyPatJwtSignature(
  token: string,
  secret: string,
): Promise<boolean> {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const expected = await hmacSha256(secret, `${parts[0]}.${parts[1]}`);
  const expectedB64 = base64UrlEncode(expected);
  return parts[2] === expectedB64;
}
