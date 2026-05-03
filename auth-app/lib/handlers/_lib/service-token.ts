/**
 * Service token (server-to-server JWT) issuance.
 *
 * Phase 0 P0.7 (partial — endpoint only):
 *   - audience-scoped (`aud: bsage|bsgateway|bsupervisor|bsnexus`)
 *   - explicit `scope` claim (space-delimited list, e.g. "bsage.read bsage.write")
 *   - signed with shared HS256 secret in Phase 0 — Phase 0.4 will introduce
 *     Ed25519 + JWKS rotation. The JWT *shape* is what 4 products will rely on
 *     for the bsvibe-authz verification path; the algorithm is internal.
 *
 * This module deliberately depends on Web Crypto only (no jose/jsonwebtoken)
 * to keep the Vercel function cold-start small.
 */

export const SERVICE_AUDIENCES = [
  "bsage",
  "bsgateway",
  "bsupervisor",
  "bsnexus",
  "bsvibe-auth",
] as const;

export type ServiceAudience = (typeof SERVICE_AUDIENCES)[number];

const SCOPE_PATTERN = /^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$/;
const BSVIBE_AUTH_INTERNAL_SCOPES = new Set(["audit.write"]);

const DEFAULT_TTL_S = 3600; // 1 hour
const MIN_TTL_S = 60;
const MAX_TTL_S = 24 * 3600; // 24 hours — service tokens should refresh.

export interface IssueServiceTokenInput {
  audience: ServiceAudience;
  /** Scope identifiers, e.g. ["bsage.read", "bsage.write"]. Must all be prefixed with audience. */
  scope: string[];
  /** Optional override TTL in seconds. Default 3600, max 86400. */
  ttlSeconds?: number;
  /** Subject — typically `service:<name>` or the issuing user UUID for delegated calls. */
  subject: string;
  /** Optional active tenant context propagated to the recipient. */
  tenantId?: string;
}

export interface IssueServiceTokenConfig {
  /** HS256 signing secret. */
  signingSecret: string;
  /** Token issuer URL — should match `auth.bsvibe.dev`. */
  issuer: string;
  /** Override clock for tests. */
  now?: () => number;
}

export interface ServiceTokenPayload {
  iss: string;
  sub: string;
  aud: ServiceAudience;
  scope: string;
  iat: number;
  exp: number;
  /** Token type marker — distinguishes from user session JWTs. */
  token_type: "service";
  /** Optional active tenant. */
  tenant_id?: string;
}

export class ServiceTokenError extends Error {
  constructor(
    public readonly code:
      | "invalid_audience"
      | "invalid_scope"
      | "scope_audience_mismatch"
      | "invalid_ttl"
      | "missing_subject"
      | "missing_secret",
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "ServiceTokenError";
  }
}

export function validateAudience(value: unknown): ServiceAudience {
  if (typeof value !== "string" || !isServiceAudience(value)) {
    throw new ServiceTokenError(
      "invalid_audience",
      `audience must be one of ${SERVICE_AUDIENCES.join(", ")}`,
    );
  }
  return value;
}

export function isServiceAudience(value: string): value is ServiceAudience {
  return (SERVICE_AUDIENCES as readonly string[]).includes(value);
}

export function validateScopes(
  audience: ServiceAudience,
  scopes: unknown,
): string[] {
  if (!Array.isArray(scopes) || scopes.length === 0) {
    throw new ServiceTokenError(
      "invalid_scope",
      "scope must be a non-empty array of strings",
    );
  }
  const seen = new Set<string>();
  for (const s of scopes) {
    if (typeof s !== "string" || !SCOPE_PATTERN.test(s)) {
      throw new ServiceTokenError(
        "invalid_scope",
        `invalid scope format: ${String(s)}`,
      );
    }
    if (
      !s.startsWith(`${audience}.`) &&
      !(audience === "bsvibe-auth" && BSVIBE_AUTH_INTERNAL_SCOPES.has(s))
    ) {
      throw new ServiceTokenError(
        "scope_audience_mismatch",
        `scope ${s} does not match audience ${audience}`,
      );
    }
    seen.add(s);
  }
  return [...seen].sort();
}

export function validateTtl(ttl: unknown): number {
  if (ttl === undefined || ttl === null) return DEFAULT_TTL_S;
  if (typeof ttl !== "number" || !Number.isFinite(ttl) || !Number.isInteger(ttl)) {
    throw new ServiceTokenError(
      "invalid_ttl",
      "ttl_s must be a positive integer",
    );
  }
  if (ttl < MIN_TTL_S || ttl > MAX_TTL_S) {
    throw new ServiceTokenError(
      "invalid_ttl",
      `ttl_s must be between ${MIN_TTL_S} and ${MAX_TTL_S}`,
    );
  }
  return ttl;
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

export async function issueServiceToken(
  input: IssueServiceTokenInput,
  cfg: IssueServiceTokenConfig,
): Promise<{ access_token: string; expires_in: number; payload: ServiceTokenPayload }> {
  if (!cfg.signingSecret) {
    throw new ServiceTokenError(
      "missing_secret",
      "service token signing secret not configured",
    );
  }
  if (!input.subject) {
    throw new ServiceTokenError(
      "missing_subject",
      "subject is required",
    );
  }

  const audience = validateAudience(input.audience);
  const scopes = validateScopes(audience, input.scope);
  const ttl = validateTtl(input.ttlSeconds);

  const now = Math.floor((cfg.now ? cfg.now() : Date.now()) / 1000);
  const payload: ServiceTokenPayload = {
    iss: cfg.issuer,
    sub: input.subject,
    aud: audience,
    scope: scopes.join(" "),
    iat: now,
    exp: now + ttl,
    token_type: "service",
    ...(input.tenantId ? { tenant_id: input.tenantId } : {}),
  };

  const header = { alg: "HS256", typ: "JWT" } as const;
  const headerEnc = base64UrlEncodeJSON(header);
  const payloadEnc = base64UrlEncodeJSON(payload);
  const signingInput = `${headerEnc}.${payloadEnc}`;
  const signature = await hmacSha256(cfg.signingSecret, signingInput);
  const sigEnc = base64UrlEncode(signature);

  return {
    access_token: `${signingInput}.${sigEnc}`,
    expires_in: ttl,
    payload,
  };
}

export function decodeJwtPayload<T = unknown>(token: string): T {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("invalid_jwt");
  const padded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (padded.length % 4)) % 4;
  return JSON.parse(atob(padded + "=".repeat(padLen))) as T;
}

export async function verifyServiceTokenSignature(
  token: string,
  secret: string,
): Promise<boolean> {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const expected = await hmacSha256(secret, `${parts[0]}.${parts[1]}`);
  const expectedB64 = base64UrlEncode(expected);
  return parts[2] === expectedB64;
}
