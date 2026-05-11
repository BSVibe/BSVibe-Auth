/**
 * Token primitives for personal access tokens (PATs) and opaque API keys.
 *
 * - Opaque tokens: base62 random body with a `bsv_sk_` / `bsv_pk_` prefix.
 *   Stored as sha256(raw); only the first 12 chars (prefix) are stored
 *   in plaintext for index lookup.
 * - PAT JWTs: HS256 signed with the same secret as service tokens. Distinct
 *   `token_type: "pat"` claim distinguishes them from service-to-service JWTs.
 * - Refresh tokens: 32-byte urlsafe base64 random; stored as sha256(raw).
 *
 * Web Crypto only — no jose / jsonwebtoken dependency.
 */

import { base64UrlEncode, base64UrlEncodeJSON, hmacSha256 } from "./jwt-crypto";

const BASE62_ALPHABET =
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

const OPAQUE_RANDOM_BYTES = 32;

/** Length of the prefix slice stored in the `tokens.prefix` index column. */
export const OPAQUE_PREFIX_LEN = 12;
const REFRESH_RANDOM_BYTES = 32;

export type OpaquePrefix = "bsv_sk_" | "bsv_pk_";

export interface OpaqueToken {
  raw: string;
  prefix: string;
  hash: Uint8Array;
}

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

function base62Encode(bytes: Uint8Array): string {
  // Treat the byte array as a big-endian integer; encode to base62.
  // For 32 random bytes the encoded length is ~43 chars.
  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      const v = digits[j] * 256 + carry;
      digits[j] = v % 62;
      carry = Math.floor(v / 62);
    }
    while (carry > 0) {
      digits.push(carry % 62);
      carry = Math.floor(carry / 62);
    }
  }
  // Preserve leading zero bytes as leading "0" base62 digits to keep length stable.
  for (const byte of bytes) {
    if (byte === 0) digits.push(0);
    else break;
  }
  let out = "";
  for (let i = digits.length - 1; i >= 0; i--) out += BASE62_ALPHABET[digits[i]];
  return out;
}


/**
 * Generate an opaque API key with the given prefix.
 * Returns the raw token (shown to the user once), the 12-char prefix used as a
 * DB lookup index, and the sha256(raw) hash to store in `tokens.token_hash`.
 */
export async function generateOpaqueToken(
  prefix: OpaquePrefix,
): Promise<OpaqueToken> {
  const random = crypto.getRandomValues(new Uint8Array(OPAQUE_RANDOM_BYTES));
  const body = base62Encode(random);
  const raw = `${prefix}${body}`;
  const hash = await sha256Bytes(raw);
  return { raw, prefix: raw.slice(0, OPAQUE_PREFIX_LEN), hash };
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
