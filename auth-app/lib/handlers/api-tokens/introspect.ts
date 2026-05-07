/**
 * POST /api/tokens/introspect — RFC 7662 OAuth 2.0 Token Introspection.
 *
 * Resource servers (gateway, sage, nexus, supervisor) call this with a token
 * they received from a user request to confirm it is still active and learn
 * its scope/aud/sub. Caller authenticates via HTTP Basic using an
 * `oauth_clients` row (same identities used by /api/oauth/token).
 *
 * Token shape detection:
 *   - `bsv_sk_…` / `bsv_pk_…` → opaque API key. Lookup by sha256 hash + 12-char
 *     prefix index. Active iff revoked_at IS NULL AND (expires_at IS NULL OR
 *     expires_at > now()).
 *   - 3 dot-separated segments → PAT JWT. Verify HS256 signature with
 *     SERVICE_TOKEN_SIGNING_SECRET; check exp; confirm not revoked by jti
 *     lookup.
 *   - Otherwise → { active: false }.
 *
 * Responses are always 200 OK per RFC 7662 §2.2 — failures from the introspector
 * never leak whether the token "looked valid". Only the caller-auth layer
 * (Basic) returns 401.
 *
 * On a successful active=true response we issue a best-effort PATCH to bump
 * tokens.last_used_at — failure of that update never affects the response.
 */

import type { VercelRequest, VercelResponse } from "../_lib/types";
import {
  parseClientCredentials,
  fetchOAuthClient,
  verifyClientSecret,
  type OAuthClientRecord,
} from "../_lib/oauth-client";
import {
  bytesToHex,
  decodePatJwtPayload,
  OPAQUE_PREFIX_LEN,
  sha256Bytes,
  verifyPatJwtSignature,
  type PatJwtPayload,
} from "../_lib/api-token";
import { handleCorsAndMethod, supabaseServiceHeaders } from "./_auth";

export interface IntrospectHandlerDeps {
  lookupClient?: (clientId: string) => Promise<OAuthClientRecord | null>;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

interface ParsedBody {
  token?: string;
  token_type_hint?: string;
}

interface TokenRow {
  id: string;
  user_id: string;
  tenant_id: string;
  type: "pat" | "api_key";
  audience: string[];
  scopes: string[];
  expires_at: string | null;
  revoked_at: string | null;
}

const OPAQUE_PREFIXES = ["bsv_sk_", "bsv_pk_"] as const;
const TOKEN_LOOKUP_FIELDS =
  "id,user_id,tenant_id,type,audience,scopes,expires_at,revoked_at";

function parseFormUrlEncoded(raw: string): ParsedBody {
  const params = new URLSearchParams(raw);
  const out: ParsedBody = {};
  const t = params.get("token");
  const h = params.get("token_type_hint");
  if (typeof t === "string") out.token = t;
  if (typeof h === "string") out.token_type_hint = h;
  return out;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function readBody(req: VercelRequest): ParsedBody {
  const ct = (req.headers["content-type"] ?? "").toLowerCase();
  const raw = req.body;
  if (typeof raw === "string") {
    if (ct.includes("application/x-www-form-urlencoded")) {
      return parseFormUrlEncoded(raw);
    }
    try {
      const j = JSON.parse(raw) as Record<string, unknown>;
      return {
        token: typeof j.token === "string" ? j.token : undefined,
        token_type_hint:
          typeof j.token_type_hint === "string" ? j.token_type_hint : undefined,
      };
    } catch {
      return {};
    }
  }
  if (isPlainObject(raw)) {
    return {
      token: typeof raw.token === "string" ? raw.token : undefined,
      token_type_hint:
        typeof raw.token_type_hint === "string"
          ? raw.token_type_hint
          : undefined,
    };
  }
  return {};
}

function looksLikeOpaque(token: string): boolean {
  return OPAQUE_PREFIXES.some((p) => token.startsWith(p));
}

function looksLikeJwt(token: string): boolean {
  const parts = token.split(".");
  return parts.length === 3 && parts.every((p) => p.length > 0);
}

function bytesToPgHex(b: Uint8Array): string {
  return `\\x${bytesToHex(b)}`;
}

function expiresAtEpoch(expiresAt: string | null): number | undefined {
  if (!expiresAt) return undefined;
  const t = Date.parse(expiresAt);
  if (Number.isNaN(t)) return undefined;
  return Math.floor(t / 1000);
}

function isExpired(row: TokenRow, nowMs: number): boolean {
  if (!row.expires_at) return false;
  const t = Date.parse(row.expires_at);
  if (Number.isNaN(t)) return false;
  return t <= nowMs;
}

interface SupabaseEnv {
  url: string;
  serviceRoleKey: string;
}

async function lookupOpaque(
  env: SupabaseEnv,
  fetchImpl: typeof fetch,
  prefix: string,
  hash: Uint8Array,
): Promise<TokenRow | null> {
  const url = new URL(`${env.url}/rest/v1/tokens`);
  url.searchParams.set("select", TOKEN_LOOKUP_FIELDS);
  url.searchParams.set("prefix", `eq.${prefix}`);
  url.searchParams.set("token_hash", `eq.${bytesToPgHex(hash)}`);
  url.searchParams.set("revoked_at", "is.null");
  url.searchParams.set("limit", "1");
  const resp = await fetchImpl(url.toString(), {
    headers: supabaseServiceHeaders(env),
  });
  if (!resp.ok) return null;
  const rows = (await resp.json()) as TokenRow[];
  if (!Array.isArray(rows) || rows.length === 0) return null;
  return rows[0];
}

async function lookupByJti(
  env: SupabaseEnv,
  fetchImpl: typeof fetch,
  jti: string,
): Promise<TokenRow | null> {
  const url = new URL(`${env.url}/rest/v1/tokens`);
  url.searchParams.set("select", TOKEN_LOOKUP_FIELDS);
  url.searchParams.set("jti", `eq.${jti}`);
  url.searchParams.set("revoked_at", "is.null");
  url.searchParams.set("limit", "1");
  const resp = await fetchImpl(url.toString(), {
    headers: supabaseServiceHeaders(env),
  });
  if (!resp.ok) return null;
  const rows = (await resp.json()) as TokenRow[];
  if (!Array.isArray(rows) || rows.length === 0) return null;
  return rows[0];
}

function touchLastUsed(
  env: SupabaseEnv,
  fetchImpl: typeof fetch,
  tokenId: string,
  nowIso: string,
): void {
  const url = new URL(`${env.url}/rest/v1/tokens`);
  url.searchParams.set("id", `eq.${tokenId}`);
  void fetchImpl(url.toString(), {
    method: "PATCH",
    headers: {
      ...supabaseServiceHeaders(env),
      "Content-Type": "application/json",
      Prefer: "return=minimal",
    },
    body: JSON.stringify({ last_used_at: nowIso }),
  }).catch(() => undefined);
}

interface IntrospectionResponse {
  active: boolean;
  sub?: string;
  tenant?: string;
  aud?: string[];
  scope?: string;
  exp?: number;
  client_id?: string;
  token_type?: "api_key" | "pat";
  jti?: string;
}

function buildActive(
  row: TokenRow,
  callerClientId: string,
  patExp?: number,
  jti?: string,
): IntrospectionResponse {
  const exp = patExp ?? expiresAtEpoch(row.expires_at);
  const out: IntrospectionResponse = {
    active: true,
    sub: row.user_id,
    tenant: row.tenant_id,
    aud: Array.isArray(row.audience) ? row.audience : [],
    scope: Array.isArray(row.scopes) ? row.scopes.join(" ") : "",
    client_id: callerClientId,
    token_type: row.type,
  };
  if (typeof exp === "number") out.exp = exp;
  if (jti) out.jti = jti;
  return out;
}

export function createIntrospectHandler(deps: IntrospectHandlerDeps = {}) {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const now = deps.now ?? Date.now;
  const lookupClient =
    deps.lookupClient ??
    ((id: string) => {
      const url = process.env.SUPABASE_URL;
      const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
      if (!url || !key) return Promise.resolve(null);
      return fetchOAuthClient({ url, serviceRoleKey: key }, id, fetchImpl);
    });

  return async function handler(req: VercelRequest, res: VercelResponse) {
    if (handleCorsAndMethod(req, res, "POST")) return;

    // Caller authentication (RFC 7662 §2.1).
    const credentials = parseClientCredentials(req.headers.authorization, {});
    if (!credentials) {
      res.setHeader("WWW-Authenticate", 'Basic realm="oauth_clients"');
      return res.status(401).json({ error: "invalid_client" });
    }
    const clientRecord = await lookupClient(credentials.clientId);
    if (!clientRecord || clientRecord.revoked_at !== null) {
      return res.status(401).json({ error: "invalid_client" });
    }
    const credOk = await verifyClientSecret(
      credentials.clientSecret,
      clientRecord.client_secret_hash,
    );
    if (!credOk) {
      return res.status(401).json({ error: "invalid_client" });
    }

    const body = readBody(req);
    if (!body.token || typeof body.token !== "string" || body.token.length === 0) {
      return res
        .status(400)
        .json({ error: "invalid_request", error_description: "token is required" });
    }

    const supabaseUrl = process.env.SUPABASE_URL;
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!supabaseUrl || !serviceRoleKey) {
      return res.status(500).json({ error: "Auth service not configured" });
    }
    const env: SupabaseEnv = { url: supabaseUrl, serviceRoleKey };

    const token = body.token;
    const nowMs = now();
    const inactive = (): VercelResponse => res.status(200).json({ active: false });

    // Branch 1: opaque API key.
    if (looksLikeOpaque(token)) {
      if (token.length <= OPAQUE_PREFIX_LEN) return inactive();
      const prefix = token.slice(0, OPAQUE_PREFIX_LEN);
      const hash = await sha256Bytes(token);
      const row = await lookupOpaque(env, fetchImpl, prefix, hash).catch(
        () => null,
      );
      if (!row) return inactive();
      if (isExpired(row, nowMs)) return inactive();
      touchLastUsed(env, fetchImpl, row.id, new Date(nowMs).toISOString());
      return res
        .status(200)
        .json(buildActive(row, credentials.clientId));
    }

    // Branch 2: PAT JWT.
    if (looksLikeJwt(token)) {
      const signingSecret = process.env.SERVICE_TOKEN_SIGNING_SECRET;
      if (!signingSecret) return inactive();
      const sigOk = await verifyPatJwtSignature(token, signingSecret).catch(
        () => false,
      );
      if (!sigOk) return inactive();
      let payload: PatJwtPayload;
      try {
        payload = decodePatJwtPayload<PatJwtPayload>(token);
      } catch {
        return inactive();
      }
      if (payload.token_type !== "pat") return inactive();
      const expSec = typeof payload.exp === "number" ? payload.exp : 0;
      if (!expSec || expSec * 1000 <= nowMs) return inactive();
      if (typeof payload.jti !== "string" || payload.jti.length === 0) {
        return inactive();
      }
      const row = await lookupByJti(env, fetchImpl, payload.jti).catch(
        () => null,
      );
      if (!row) return inactive();
      if (isExpired(row, nowMs)) return inactive();
      touchLastUsed(env, fetchImpl, row.id, new Date(nowMs).toISOString());
      return res
        .status(200)
        .json(buildActive(row, credentials.clientId, expSec, payload.jti));
    }

    return inactive();
  };
}

const defaultHandler = createIntrospectHandler();
export default defaultHandler;
