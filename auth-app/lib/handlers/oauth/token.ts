/**
 * POST /api/oauth/token — OAuth2 client_credentials grant.
 *
 * Replaces the bootstrap flow where 4 backends presented a Supabase admin
 * access_token (1h, launchd-rotated) to /api/service-tokens/issue. Each
 * backend now has its own oauth_clients row and exchanges client_id +
 * client_secret directly for an audience-scoped service JWT.
 *
 * Spec extracts (RFC 6749 §4.4):
 *   - grant_type=client_credentials
 *   - client authentication: HTTP Basic (preferred) OR body params
 *   - audience: required (BSVibe extension; aligns with service-token.ts)
 *   - scope: optional, space-delimited; defaults to allowed_scopes
 *
 * Error codes use the OAuth2 surface (`invalid_request`, `invalid_client`,
 * `unsupported_grant_type`, `invalid_scope`, `invalid_target`) so that
 * clients can react to them with off-the-shelf libraries.
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

export interface OAuthTokenHandlerDeps {
  /** Override the Supabase row lookup (test seam). */
  lookupClient?: (clientId: string) => Promise<OAuthClientRecord | null>;
  /** Override the best-effort last_used_at bump (test seam). */
  touchLastUsed?: (clientId: string) => Promise<void>;
  fetchImpl?: typeof fetch;
}

interface ParsedBody {
  grant_type?: string;
  audience?: string;
  scope?: string;
  client_id?: string;
  client_secret?: string;
}

function parseFormUrlEncoded(raw: string): ParsedBody {
  const params = new URLSearchParams(raw);
  const out: ParsedBody = {};
  for (const [k, v] of params) {
    (out as Record<string, string>)[k] = v;
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
    for (const k of [
      "grant_type",
      "audience",
      "scope",
      "client_id",
      "client_secret",
    ] as const) {
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
      description
        ? { error, error_description: description }
        : { error },
    );
}

export function createOAuthTokenHandler(deps: OAuthTokenHandlerDeps = {}) {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const lookupClient =
    deps.lookupClient ??
    ((id: string) => {
      const url = process.env.SUPABASE_URL;
      const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
      if (!url || !key) return Promise.resolve(null);
      return fetchOAuthClient({ url, serviceRoleKey: key }, id, fetchImpl);
    });
  const touchLastUsed =
    deps.touchLastUsed ??
    ((id: string) => {
      const url = process.env.SUPABASE_URL;
      const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
      if (!url || !key) return Promise.resolve();
      return touchOAuthClientLastUsed(
        { url, serviceRoleKey: key },
        id,
        fetchImpl,
      );
    });

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
    if (body.grant_type !== "client_credentials") {
      return oauthError(
        res,
        400,
        "unsupported_grant_type",
        "only client_credentials is supported",
      );
    }
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
          tenantId: record.tenant_id,
        },
        { signingSecret, issuer },
      );
      // Best-effort: do not fail the mint on a metrics update.
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
  };
}

const defaultHandler = createOAuthTokenHandler();
export default defaultHandler;
