/**
 * POST /api/oauth/token — OAuth2 token endpoint.
 *
 * Dispatches by `grant_type`:
 *  - `client_credentials`: machine-to-machine (PR #7, untouched).
 *  - `refresh_token`: single-use rotation of a PAT refresh token. Detects
 *    reuse and revokes the parent token + sibling refresh rows.
 *  - `urn:ietf:params:oauth:grant-type:device_code`: claims an `approved`
 *    device_codes row and mints a PAT bound to the client's tenant.
 *
 * Spec extracts (RFC 6749 §4.4 / §6, RFC 8628 §3.4):
 *  - audience required for client_credentials only (BSVibe extension).
 *  - refresh_token grant: response carries new access_token + new refresh_token.
 *  - device_code grant: standard error codes `authorization_pending`,
 *    `slow_down`, `expired_token`, `access_denied`.
 *
 * Error codes use the OAuth2 surface (`invalid_request`, `invalid_client`,
 * `invalid_grant`, `unsupported_grant_type`, `invalid_scope`, `invalid_target`).
 */

import type { VercelRequest, VercelResponse } from "../_lib/types";
import {
  parseClientCredentials,
  fetchOAuthClient,
  touchOAuthClientLastUsed,
  verifyClientSecret,
  type OAuthClientRecord,
} from "../_lib/oauth-client";
import {
  issueServiceToken,
  ServiceTokenError,
  validateAudience,
  type ServiceAudience,
} from "../_lib/service-token";
import {
  generatePatJwt,
  generateRefreshToken,
  sha256Bytes,
  bytesToHex,
} from "../_lib/api-token";
import {
  emitAuditEventBestEffort,
  type AuditEmitInput,
} from "../_lib/audit-emit";
import { claimDeviceCode as claimDeviceCodeImpl } from "./device/token";
import type { ClaimDeviceCodeOutcome } from "./device/token";

const CLIENT_CREDENTIALS_GRANT = "client_credentials";
const REFRESH_TOKEN_GRANT = "refresh_token";
const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const PAT_TTL_S = 60 * 60; // 1h
const REFRESH_TTL_S = 30 * 24 * 60 * 60; // 30d

export interface TokenRecord {
  id: string;
  user_id: string;
  tenant_id: string;
  type: "pat" | "api_key";
  audience: string[];
  scopes: string[];
  revoked_at: string | null;
  expires_at: string | null;
}

export interface PatTokenInsertRow {
  id: string;
  user_id: string;
  tenant_id: string;
  type: "pat";
  jti: string;
  audience: string[];
  scopes: string[];
  name: string;
  expires_at: string;
}

export type RefreshConsumeOutcome =
  | { kind: "consumed"; tokenId: string; refreshId: string }
  | { kind: "race"; tokenId: string }
  | { kind: "invalid" };

export interface OAuthTokenHandlerDeps {
  /** Override the Supabase row lookup (test seam). */
  lookupClient?: (clientId: string) => Promise<OAuthClientRecord | null>;
  /** Override the best-effort last_used_at bump (test seam). */
  touchLastUsed?: (clientId: string) => Promise<void>;
  fetchImpl?: typeof fetch;
  /** refresh_token grant: atomic single-use claim of a refresh row. */
  consumeRefreshToken?: (rawToken: string) => Promise<RefreshConsumeOutcome>;
  /** Lookup the parent token row by id (PAT issuance + race audit context). */
  getTokenRecord?: (tokenId: string) => Promise<TokenRecord | null>;
  /** Insert a new refresh_tokens row tied to tokenId. */
  insertRefreshTokenRow?: (
    tokenId: string,
    hash: Uint8Array,
    expiresAt: string,
  ) => Promise<boolean>;
  /** Race fallback: revoke parent token + invalidate all sibling refresh rows. */
  revokeTokenForRace?: (tokenId: string) => Promise<void>;
  /** device_code grant: atomic claim returning principal + scope/audience. */
  claimDeviceCode?: (
    deviceCode: string,
    clientId: string,
  ) => Promise<ClaimDeviceCodeOutcome>;
  /** Insert a tokens row for a freshly-minted device-flow PAT. */
  insertPatTokenRow?: (row: PatTokenInsertRow) => Promise<boolean>;
  /** Audit emit (best-effort). */
  emitAudit?: (input: AuditEmitInput) => Promise<void>;
  now?: () => number;
}

interface ParsedBody {
  grant_type?: string;
  audience?: string;
  scope?: string;
  client_id?: string;
  client_secret?: string;
  refresh_token?: string;
  device_code?: string;
}

const PARSED_KEYS = [
  "grant_type",
  "audience",
  "scope",
  "client_id",
  "client_secret",
  "refresh_token",
  "device_code",
] as const;

function parseFormUrlEncoded(raw: string): ParsedBody {
  const params = new URLSearchParams(raw);
  const out: ParsedBody = {};
  for (const k of PARSED_KEYS) {
    const v = params.get(k);
    if (v !== null) (out as Record<string, string>)[k] = v;
  }
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
      return JSON.parse(raw) as ParsedBody;
    } catch {
      return {};
    }
  }
  if (isPlainObject(raw)) {
    const out: ParsedBody = {};
    for (const k of PARSED_KEYS) {
      const v = raw[k];
      if (typeof v === "string") out[k] = v;
    }
    return out;
  }
  return {};
}

function oauthError(
  res: VercelResponse,
  status: number,
  error: string,
  description?: string,
  extraHeaders?: Record<string, string>,
) {
  if (extraHeaders) {
    for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
  }
  return res
    .status(status)
    .json(
      description ? { error, error_description: description } : { error },
    );
}

function bytesToPgHex(b: Uint8Array): string {
  return `\\x${bytesToHex(b)}`;
}

function defaultLookupClient(fetchImpl: typeof fetch) {
  return (id: string) => {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!url || !key) return Promise.resolve(null);
    return fetchOAuthClient({ url, serviceRoleKey: key }, id, fetchImpl);
  };
}

function defaultTouchLastUsed(fetchImpl: typeof fetch) {
  return (id: string) => {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!url || !key) return Promise.resolve();
    return touchOAuthClientLastUsed(
      { url, serviceRoleKey: key },
      id,
      fetchImpl,
    );
  };
}

function defaultEmitAudit(
  fetchImpl: typeof fetch,
): (input: AuditEmitInput) => Promise<void> {
  return async (input) => {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!url || !key) return;
    await emitAuditEventBestEffort(
      { url, serviceRoleKey: key },
      input,
      { fetchImpl },
    );
  };
}

function defaultConsumeRefreshToken(
  fetchImpl: typeof fetch,
  now: () => number,
): (rawToken: string) => Promise<RefreshConsumeOutcome> {
  return async (rawToken) => {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!url || !key) return { kind: "invalid" };
    const hashHex = bytesToPgHex(await sha256Bytes(rawToken));
    const nowIso = new Date(now()).toISOString();

    // 1) Atomic single-use claim: only un-used + non-expired rows transition.
    const claimUrl = new URL(`${url}/rest/v1/refresh_tokens`);
    claimUrl.searchParams.set("hash", `eq.${hashHex}`);
    claimUrl.searchParams.set("used_at", "is.null");
    claimUrl.searchParams.set("expires_at", `gt.${nowIso}`);
    const claimResp = await fetchImpl(claimUrl.toString(), {
      method: "PATCH",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=representation",
      },
      body: JSON.stringify({ used_at: nowIso }),
    });
    if (claimResp.ok) {
      const rows = (await claimResp.json()) as Array<{
        id: string;
        token_id: string;
      }>;
      if (Array.isArray(rows) && rows.length === 1) {
        return {
          kind: "consumed",
          tokenId: rows[0].token_id,
          refreshId: rows[0].id,
        };
      }
    }

    // 2) Diagnostic: row may be reused (used_at populated) or unknown/expired.
    const lookupUrl = new URL(`${url}/rest/v1/refresh_tokens`);
    lookupUrl.searchParams.set("select", "id,token_id,used_at,expires_at");
    lookupUrl.searchParams.set("hash", `eq.${hashHex}`);
    lookupUrl.searchParams.set("limit", "1");
    const lookupResp = await fetchImpl(lookupUrl.toString(), {
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        Accept: "application/json",
      },
    });
    if (!lookupResp.ok) return { kind: "invalid" };
    const rows = (await lookupResp.json()) as Array<{
      id: string;
      token_id: string;
      used_at: string | null;
    }>;
    if (!Array.isArray(rows) || rows.length === 0) {
      return { kind: "invalid" };
    }
    if (rows[0].used_at !== null) {
      return { kind: "race", tokenId: rows[0].token_id };
    }
    return { kind: "invalid" };
  };
}

function defaultGetTokenRecord(
  fetchImpl: typeof fetch,
): (tokenId: string) => Promise<TokenRecord | null> {
  return async (tokenId) => {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!url || !key) return null;
    const lookupUrl = new URL(`${url}/rest/v1/tokens`);
    lookupUrl.searchParams.set(
      "select",
      "id,user_id,tenant_id,type,audience,scopes,revoked_at,expires_at",
    );
    lookupUrl.searchParams.set("id", `eq.${tokenId}`);
    lookupUrl.searchParams.set("limit", "1");
    const resp = await fetchImpl(lookupUrl.toString(), {
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        Accept: "application/json",
      },
    });
    if (!resp.ok) return null;
    const rows = (await resp.json()) as TokenRecord[];
    if (!Array.isArray(rows) || rows.length === 0) return null;
    return rows[0];
  };
}

function defaultInsertRefreshTokenRow(
  fetchImpl: typeof fetch,
): (
  tokenId: string,
  hash: Uint8Array,
  expiresAt: string,
) => Promise<boolean> {
  return async (tokenId, hash, expiresAt) => {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!url || !key) return false;
    const resp = await fetchImpl(`${url}/rest/v1/refresh_tokens`, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=minimal",
      },
      body: JSON.stringify({
        token_id: tokenId,
        hash: bytesToPgHex(hash),
        expires_at: expiresAt,
      }),
    });
    return resp.ok;
  };
}

function defaultRevokeTokenForRace(
  fetchImpl: typeof fetch,
  now: () => number,
): (tokenId: string) => Promise<void> {
  return async (tokenId) => {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!url || !key) return;
    const nowIso = new Date(now()).toISOString();
    const headers = {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      Prefer: "return=minimal",
    } as const;
    // Revoke parent token (only if not already revoked).
    const tokenUrl = new URL(`${url}/rest/v1/tokens`);
    tokenUrl.searchParams.set("id", `eq.${tokenId}`);
    tokenUrl.searchParams.set("revoked_at", "is.null");
    await fetchImpl(tokenUrl.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({ revoked_at: nowIso }),
    }).catch(() => undefined);
    // Invalidate every still-live sibling refresh row.
    const refreshUrl = new URL(`${url}/rest/v1/refresh_tokens`);
    refreshUrl.searchParams.set("token_id", `eq.${tokenId}`);
    refreshUrl.searchParams.set("used_at", "is.null");
    await fetchImpl(refreshUrl.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({ used_at: nowIso }),
    }).catch(() => undefined);
  };
}

function defaultClaimDeviceCode(
  fetchImpl: typeof fetch,
  now: () => number,
): (deviceCode: string, clientId: string) => Promise<ClaimDeviceCodeOutcome> {
  return (deviceCode, clientId) => {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!url || !key) return Promise.resolve({ kind: "not_found" });
    return claimDeviceCodeImpl(
      { url, serviceRoleKey: key },
      deviceCode,
      clientId,
      { fetchImpl, now },
    );
  };
}

function defaultInsertPatTokenRow(
  fetchImpl: typeof fetch,
): (row: PatTokenInsertRow) => Promise<boolean> {
  return async (row) => {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!url || !key) return false;
    const resp = await fetchImpl(`${url}/rest/v1/tokens`, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=minimal",
      },
      body: JSON.stringify({
        id: row.id,
        user_id: row.user_id,
        tenant_id: row.tenant_id,
        type: row.type,
        prefix: null,
        token_hash: null,
        jti: row.jti,
        audience: row.audience,
        scopes: row.scopes,
        name: row.name,
        expires_at: row.expires_at,
      }),
    });
    return resp.ok;
  };
}

export function createOAuthTokenHandler(deps: OAuthTokenHandlerDeps = {}) {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const now = deps.now ?? Date.now;
  const lookupClient = deps.lookupClient ?? defaultLookupClient(fetchImpl);
  const touchLastUsed =
    deps.touchLastUsed ?? defaultTouchLastUsed(fetchImpl);
  const consumeRefreshToken =
    deps.consumeRefreshToken ?? defaultConsumeRefreshToken(fetchImpl, now);
  const getTokenRecord =
    deps.getTokenRecord ?? defaultGetTokenRecord(fetchImpl);
  const insertRefreshTokenRow =
    deps.insertRefreshTokenRow ?? defaultInsertRefreshTokenRow(fetchImpl);
  const revokeTokenForRace =
    deps.revokeTokenForRace ?? defaultRevokeTokenForRace(fetchImpl, now);
  const claimDeviceCode =
    deps.claimDeviceCode ?? defaultClaimDeviceCode(fetchImpl, now);
  const insertPatTokenRow =
    deps.insertPatTokenRow ?? defaultInsertPatTokenRow(fetchImpl);
  const emitAudit = deps.emitAudit ?? defaultEmitAudit(fetchImpl);

  return async function handler(req: VercelRequest, res: VercelResponse) {
    if (req.method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
      res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization",
      );
      return res.status(204).end();
    }

    if (req.method !== "POST") {
      return res.status(405).json({ error: "Method not allowed" });
    }

    const signingSecret = process.env.SERVICE_TOKEN_SIGNING_SECRET;
    const issuer =
      process.env.SERVICE_TOKEN_ISSUER || "https://auth.bsvibe.dev";
    if (!signingSecret) {
      return res
        .status(500)
        .json({ error: "Service token signing secret not configured" });
    }

    const body = readBody(req);

    if (!body.grant_type) {
      return oauthError(res, 400, "invalid_request", "grant_type is required");
    }

    switch (body.grant_type) {
      case CLIENT_CREDENTIALS_GRANT:
        return handleClientCredentials({
          req,
          res,
          body,
          signingSecret,
          issuer,
          lookupClient,
          touchLastUsed,
        });
      case REFRESH_TOKEN_GRANT:
        return handleRefreshToken({
          res,
          body,
          signingSecret,
          issuer,
          now,
          consumeRefreshToken,
          getTokenRecord,
          insertRefreshTokenRow,
          revokeTokenForRace,
          emitAudit,
        });
      case DEVICE_CODE_GRANT:
        return handleDeviceCode({
          res,
          body,
          signingSecret,
          issuer,
          now,
          lookupClient,
          claimDeviceCode,
          insertPatTokenRow,
          insertRefreshTokenRow,
          emitAudit,
        });
      default:
        return oauthError(
          res,
          400,
          "unsupported_grant_type",
          `grant_type ${body.grant_type} is not supported`,
        );
    }
  };
}

interface ClientCredentialsCtx {
  req: VercelRequest;
  res: VercelResponse;
  body: ParsedBody;
  signingSecret: string;
  issuer: string;
  lookupClient: (id: string) => Promise<OAuthClientRecord | null>;
  touchLastUsed: (id: string) => Promise<void>;
}

async function handleClientCredentials(ctx: ClientCredentialsCtx) {
  const { req, res, body, signingSecret, issuer, lookupClient, touchLastUsed } =
    ctx;
  if (!body.audience) {
    return oauthError(res, 400, "invalid_request", "audience is required");
  }

  const credentials = parseClientCredentials(req.headers.authorization, {
    client_id: body.client_id,
    client_secret: body.client_secret,
  });
  if (!credentials) {
    return oauthError(
      res,
      401,
      "invalid_client",
      "client authentication required",
      { "WWW-Authenticate": 'Basic realm="oauth_clients"' },
    );
  }

  const record = await lookupClient(credentials.clientId);
  if (!record || record.revoked_at !== null) {
    return oauthError(res, 401, "invalid_client");
  }

  // Public clients (RFC 8628 device-flow CLIs) ship with no secret and
  // are only valid for the device-flow grant. Reject early with the
  // RFC 6749 §5.2 ``unauthorized_client`` code so the failure mode is
  // distinct from "secret mismatch".
  if (record.client_type === "public" || record.client_secret_hash === null) {
    return oauthError(
      res,
      400,
      "unauthorized_client",
      "client_credentials grant is not allowed for public clients",
    );
  }

  const ok = await verifyClientSecret(
    credentials.clientSecret,
    record.client_secret_hash,
  );
  if (!ok) {
    return oauthError(res, 401, "invalid_client");
  }

  let audience: ServiceAudience;
  try {
    audience = validateAudience(body.audience);
  } catch (e) {
    if (e instanceof ServiceTokenError) {
      return oauthError(res, 400, "invalid_target", e.message);
    }
    throw e;
  }
  if (!record.allowed_audiences.includes(audience)) {
    return oauthError(
      res,
      400,
      "invalid_target",
      `audience ${audience} is not allowed for this client`,
    );
  }

  const requestedScopes =
    typeof body.scope === "string" && body.scope.trim().length > 0
      ? body.scope.trim().split(/\s+/)
      : null;
  const allowedSet = new Set(record.allowed_scopes);
  const scopes = requestedScopes ?? record.allowed_scopes.slice();
  for (const s of scopes) {
    if (!allowedSet.has(s)) {
      return oauthError(
        res,
        400,
        "invalid_scope",
        `scope ${s} is not allowed for this client`,
      );
    }
  }

  try {
    const result = await issueServiceToken(
      {
        audience,
        scope: scopes,
        subject: `client:${credentials.clientId}`,
        // Confidential clients always carry a tenant per the DB CHECK
        // (`oauth_clients_confidential_complete`); the ?? guards against
        // TS narrowing alone.
        tenantId: record.tenant_id ?? undefined,
      },
      { signingSecret, issuer },
    );
    void touchLastUsed(credentials.clientId);
    return res.status(200).json({
      access_token: result.access_token,
      expires_in: result.expires_in,
      token_type: "Bearer",
      scope: result.payload.scope,
    });
  } catch (e) {
    if (e instanceof ServiceTokenError) {
      const code =
        e.code === "invalid_audience" || e.code === "scope_audience_mismatch"
          ? "invalid_target"
          : e.code === "invalid_scope"
            ? "invalid_scope"
            : "invalid_request";
      return oauthError(res, 400, code, e.message);
    }
    throw e;
  }
}

interface RefreshTokenCtx {
  res: VercelResponse;
  body: ParsedBody;
  signingSecret: string;
  issuer: string;
  now: () => number;
  consumeRefreshToken: (rawToken: string) => Promise<RefreshConsumeOutcome>;
  getTokenRecord: (tokenId: string) => Promise<TokenRecord | null>;
  insertRefreshTokenRow: (
    tokenId: string,
    hash: Uint8Array,
    expiresAt: string,
  ) => Promise<boolean>;
  revokeTokenForRace: (tokenId: string) => Promise<void>;
  emitAudit: (input: AuditEmitInput) => Promise<void>;
}

async function handleRefreshToken(ctx: RefreshTokenCtx) {
  const {
    res,
    body,
    signingSecret,
    issuer,
    now,
    consumeRefreshToken,
    getTokenRecord,
    insertRefreshTokenRow,
    revokeTokenForRace,
    emitAudit,
  } = ctx;

  if (!body.refresh_token) {
    return oauthError(
      res,
      400,
      "invalid_request",
      "refresh_token is required",
    );
  }

  const outcome = await consumeRefreshToken(body.refresh_token);
  if (outcome.kind === "invalid") {
    return oauthError(res, 401, "invalid_grant");
  }
  if (outcome.kind === "race") {
    // Detected reuse — best-effort lookup for audit context, then revoke + emit.
    const parent = await getTokenRecord(outcome.tokenId).catch(() => null);
    await revokeTokenForRace(outcome.tokenId).catch(() => undefined);
    if (parent) {
      void emitAudit({
        eventType: "token.refresh_race_detected",
        tenantId: parent.tenant_id,
        actor: { type: "user", id: parent.user_id },
        data: { token_id: outcome.tokenId, type: "refresh_token_reuse" },
      });
    }
    return oauthError(res, 401, "invalid_grant", "refresh token already used");
  }

  // outcome.kind === "consumed"
  const record = await getTokenRecord(outcome.tokenId);
  if (!record) {
    return oauthError(res, 401, "invalid_grant");
  }
  if (record.revoked_at !== null || record.type !== "pat") {
    return oauthError(res, 401, "invalid_grant");
  }
  if (record.expires_at && Date.parse(record.expires_at) <= now()) {
    return oauthError(res, 401, "invalid_grant");
  }

  const nowMs = now();
  const expSec = Math.floor(nowMs / 1000) + PAT_TTL_S;
  const jti = crypto.randomUUID();
  const accessToken = await generatePatJwt(
    {
      sub: record.user_id,
      tenant: record.tenant_id,
      aud: record.audience,
      scope: record.scopes,
      jti,
      exp: expSec,
    },
    { signingSecret, issuer },
  );
  const refresh = await generateRefreshToken();
  const refreshExpiresIso = new Date(
    nowMs + REFRESH_TTL_S * 1000,
  ).toISOString();
  const inserted = await insertRefreshTokenRow(
    record.id,
    refresh.hash,
    refreshExpiresIso,
  );
  if (!inserted) {
    return res.status(502).json({ error: "Refresh rotation insert failed" });
  }

  void emitAudit({
    eventType: "token.refreshed",
    tenantId: record.tenant_id,
    actor: { type: "user", id: record.user_id },
    data: { token_id: record.id, jti },
  });

  return res.status(200).json({
    access_token: accessToken,
    refresh_token: refresh.raw,
    token_type: "Bearer",
    expires_in: PAT_TTL_S,
    scope: record.scopes.join(" "),
  });
}

interface DeviceCodeCtx {
  res: VercelResponse;
  body: ParsedBody;
  signingSecret: string;
  issuer: string;
  now: () => number;
  lookupClient: (id: string) => Promise<OAuthClientRecord | null>;
  claimDeviceCode: (
    deviceCode: string,
    clientId: string,
  ) => Promise<ClaimDeviceCodeOutcome>;
  insertPatTokenRow: (row: PatTokenInsertRow) => Promise<boolean>;
  insertRefreshTokenRow: (
    tokenId: string,
    hash: Uint8Array,
    expiresAt: string,
  ) => Promise<boolean>;
  emitAudit: (input: AuditEmitInput) => Promise<void>;
}

async function handleDeviceCode(ctx: DeviceCodeCtx) {
  const {
    res,
    body,
    signingSecret,
    issuer,
    now,
    lookupClient,
    claimDeviceCode,
    insertPatTokenRow,
    insertRefreshTokenRow,
    emitAudit,
  } = ctx;

  if (!body.device_code) {
    return oauthError(res, 400, "invalid_request", "device_code is required");
  }
  if (!body.client_id) {
    return oauthError(res, 400, "invalid_request", "client_id is required");
  }

  const client = await lookupClient(body.client_id);
  if (!client || client.revoked_at !== null) {
    return oauthError(res, 401, "invalid_client");
  }

  const outcome = await claimDeviceCode(body.device_code, body.client_id);
  switch (outcome.kind) {
    case "pending":
      return oauthError(res, 400, "authorization_pending");
    case "denied":
      return oauthError(res, 400, "access_denied");
    case "expired":
      return oauthError(res, 400, "expired_token");
    case "consumed":
    case "not_found":
      return oauthError(res, 400, "invalid_grant");
    case "claimed":
      break;
  }

  if (!outcome.userId) {
    return oauthError(
      res,
      400,
      "invalid_grant",
      "device approval is missing a principal",
    );
  }

  // Tenant resolution:
  //   - public client (cli): row's tenant_id stamped at /verify approve
  //   - confidential client: oauth_clients.tenant_id (legacy path)
  // Falling back to client.tenant_id covers the in-flight upgrade window
  // when device_codes.tenant_id is null because the row was approved
  // before this verify-handler redeploy.
  const tenantId = outcome.tenantId ?? client.tenant_id;
  if (!tenantId) {
    return oauthError(
      res,
      400,
      "invalid_grant",
      "device approval is missing a tenant; user must belong to at least one tenant",
    );
  }

  const tokenId = crypto.randomUUID();
  const jti = crypto.randomUUID();
  const nowMs = now();
  const expSec = Math.floor(nowMs / 1000) + PAT_TTL_S;
  const expiresAtIso = new Date(nowMs + PAT_TTL_S * 1000).toISOString();

  const accessToken = await generatePatJwt(
    {
      sub: outcome.userId,
      tenant: tenantId,
      aud: outcome.audience,
      scope: outcome.scope,
      jti,
      exp: expSec,
    },
    { signingSecret, issuer },
  );

  const insertedToken = await insertPatTokenRow({
    id: tokenId,
    user_id: outcome.userId,
    tenant_id: tenantId,
    type: "pat",
    jti,
    audience: outcome.audience,
    scopes: outcome.scope,
    name: `device:${body.client_id}`,
    expires_at: expiresAtIso,
  });
  if (!insertedToken) {
    return res.status(502).json({ error: "Token insert failed" });
  }

  const refresh = await generateRefreshToken();
  const refreshExpiresIso = new Date(
    nowMs + REFRESH_TTL_S * 1000,
  ).toISOString();
  const insertedRefresh = await insertRefreshTokenRow(
    tokenId,
    refresh.hash,
    refreshExpiresIso,
  );
  if (!insertedRefresh) {
    return res.status(502).json({ error: "Refresh token insert failed" });
  }

  void emitAudit({
    eventType: "token.created",
    tenantId,
    actor: { type: "user", id: outcome.userId },
    data: {
      token_id: tokenId,
      type: "pat",
      grant: "device_code",
      client_id: body.client_id,
      scopes: outcome.scope,
      audience: outcome.audience,
      jti,
    },
  });

  return res.status(200).json({
    access_token: accessToken,
    refresh_token: refresh.raw,
    token_type: "Bearer",
    expires_in: PAT_TTL_S,
    scope: outcome.scope.join(" "),
  });
}

const defaultHandler = createOAuthTokenHandler();
export default defaultHandler;
