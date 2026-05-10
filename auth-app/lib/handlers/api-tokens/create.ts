/**
 * POST /api/tokens — create a PAT JWT or an opaque API key.
 *
 * Authenticated via Supabase Bearer access_token. Caller must be a member of
 * the requested tenant. PAT creation also mints a refresh_token and inserts
 * a refresh_tokens row; opaque api_key creation stores only sha256(raw) +
 * the 12-char prefix. The raw secret is returned ONCE in the response and
 * never written to logs or audit data.
 */

import type { VercelRequest, VercelResponse } from "../_lib/types";
import {
  generateOpaqueToken,
  generatePatJwt,
  generateRefreshToken,
  bytesToHex,
} from "../_lib/api-token";
import {
  emitAuditEventBestEffort,
  type AuditEmitInput,
  type AuditEmitResult,
} from "../_lib/audit-emit";
import {
  getMembership as getMembershipImpl,
  type SupabaseConfig,
  type TenantRole,
} from "../_lib/tenants";
import {
  authenticate,
  handleCorsAndMethod,
  isUuid,
  supabaseServiceHeaders,
  verifySupabaseAccessToken,
  type VerifyAccessTokenFn,
} from "./_auth";

export type EmitAuditFn = (
  cfg: { url: string; serviceRoleKey: string },
  input: AuditEmitInput,
) => Promise<AuditEmitResult>;

export interface CreateTokenHandlerDeps {
  verifyAccessToken?: VerifyAccessTokenFn;
  getMembership?: (
    cfg: SupabaseConfig,
    userId: string,
    tenantId: string,
    fetchImpl?: typeof fetch,
  ) => Promise<TenantRole | null>;
  fetchImpl?: typeof fetch;
  emitAudit?: EmitAuditFn;
  now?: () => number;
}

interface CreateBody {
  type?: unknown;
  name?: unknown;
  scopes?: unknown;
  audience?: unknown;
  tenant_id?: unknown;
  expires_in_s?: unknown;
}

// PAT default: 30 days. The original 1h default was set defensively
// before we had a refresh path; in practice it forced operators to
// re-issue mid-task. Phase 8 dogfood (2026-05-11) caught issued PATs
// dying inside an hour and breaking running CLI flows. CLI automation
// and dashboard issuance both routinely want 30d+, and the dashboard
// picker (bsvibe-site) now defaults to 30d as well; they line up.
// Operators who want a shorter TTL still pass ``expires_in_s``
// explicitly. ``MAX_TTL_S`` (365d) is unchanged.
const DEFAULT_PAT_TTL_S = 30 * 24 * 60 * 60; // 30d
const DEFAULT_REFRESH_TTL_S = 30 * 24 * 60 * 60; // 30d
const DEFAULT_API_KEY_TTL_S = 90 * 24 * 60 * 60; // 90d
const MIN_TTL_S = 60;
const MAX_TTL_S = 365 * 24 * 60 * 60;
const NAME_MAX = 128;
const SCOPE_MAX = 64;
const SCOPE_PATTERN = /^[a-z][a-z0-9_]*(?:[:.][a-z0-9_*]+)*$/;

function bytesToPgHex(b: Uint8Array): string {
  return `\\x${bytesToHex(b)}`;
}

export function createCreateTokenHandler(deps: CreateTokenHandlerDeps = {}) {
  const verifyAccessToken = deps.verifyAccessToken ?? verifySupabaseAccessToken;
  const getMembership = deps.getMembership ?? getMembershipImpl;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const emitAudit: EmitAuditFn =
    deps.emitAudit ??
    ((cfg, input) => emitAuditEventBestEffort(cfg, input, { fetchImpl }));
  const now = deps.now ?? Date.now;

  return async function handler(req: VercelRequest, res: VercelResponse) {
    if (handleCorsAndMethod(req, res, "POST")) return;

    const auth = await authenticate(req, res, verifyAccessToken, fetchImpl);
    if (!auth) return;
    const { userId, env } = auth;

    const signingSecret = process.env.SERVICE_TOKEN_SIGNING_SECRET;
    const issuer =
      process.env.SERVICE_TOKEN_ISSUER || "https://auth.bsvibe.dev";
    if (!signingSecret) {
      return res
        .status(500)
        .json({ error: "Token signing secret not configured" });
    }

    const body = (req.body ?? {}) as CreateBody;

    if (body.type !== "pat" && body.type !== "api_key") {
      return res
        .status(400)
        .json({ error: "type must be 'pat' or 'api_key'" });
    }
    if (
      typeof body.name !== "string" ||
      body.name.length === 0 ||
      body.name.length > NAME_MAX
    ) {
      return res
        .status(400)
        .json({ error: `name is required (1..${NAME_MAX} chars)` });
    }
    if (!isUuid(body.tenant_id)) {
      return res.status(400).json({ error: "tenant_id must be a uuid" });
    }
    if (
      !Array.isArray(body.scopes) ||
      body.scopes.some(
        (s) =>
          typeof s !== "string" ||
          s.length === 0 ||
          s.length > SCOPE_MAX ||
          !SCOPE_PATTERN.test(s),
      )
    ) {
      return res
        .status(400)
        .json({ error: "scopes must be an array of valid scope strings" });
    }
    if (
      !Array.isArray(body.audience) ||
      body.audience.length === 0 ||
      body.audience.some(
        (a) => typeof a !== "string" || a.length === 0 || a.length > SCOPE_MAX,
      )
    ) {
      return res
        .status(400)
        .json({ error: "audience must be a non-empty string array" });
    }

    let ttl: number;
    if (body.expires_in_s === undefined || body.expires_in_s === null) {
      ttl = body.type === "pat" ? DEFAULT_PAT_TTL_S : DEFAULT_API_KEY_TTL_S;
    } else if (
      typeof body.expires_in_s !== "number" ||
      !Number.isInteger(body.expires_in_s) ||
      body.expires_in_s < MIN_TTL_S ||
      body.expires_in_s > MAX_TTL_S
    ) {
      return res.status(400).json({
        error: `expires_in_s must be an integer in [${MIN_TTL_S}, ${MAX_TTL_S}]`,
      });
    } else {
      ttl = body.expires_in_s;
    }

    const tenantId = body.tenant_id;
    const role = await getMembership(
      { url: env.supabaseUrl, serviceRoleKey: env.serviceRoleKey },
      userId,
      tenantId,
      fetchImpl,
    );
    if (!role) {
      return res
        .status(403)
        .json({ error: "Not a member of the requested tenant" });
    }

    const tokenId = crypto.randomUUID();
    const nowMs = now();
    const expiresAtIso = new Date(nowMs + ttl * 1000).toISOString();
    const scopes = body.scopes as string[];
    const audience = body.audience as string[];
    const name = body.name;

    const restHeaders = {
      ...supabaseServiceHeaders(env),
      "Content-Type": "application/json",
    } as const;

    if (body.type === "api_key") {
      const opaque = await generateOpaqueToken("bsv_sk_");
      const insertResp = await fetchImpl(`${env.supabaseUrl}/rest/v1/tokens`, {
        method: "POST",
        headers: { ...restHeaders, Prefer: "return=minimal" },
        body: JSON.stringify({
          id: tokenId,
          user_id: userId,
          tenant_id: tenantId,
          type: "api_key",
          prefix: opaque.prefix,
          token_hash: bytesToPgHex(opaque.hash),
          audience,
          scopes,
          name,
          expires_at: expiresAtIso,
        }),
      });
      if (!insertResp.ok) {
        return res.status(502).json({
          error: "Token insert failed",
          upstream_status: insertResp.status,
        });
      }
      void emitAudit(
        { url: env.supabaseUrl, serviceRoleKey: env.serviceRoleKey },
        {
          eventType: "token.created",
          tenantId,
          actor: { type: "user", id: userId },
          data: {
            token_id: tokenId,
            type: "api_key",
            name,
            scopes,
            audience,
            prefix: opaque.prefix,
          },
        },
      );
      return res.status(201).json({
        id: tokenId,
        type: "api_key",
        name,
        prefix: opaque.prefix,
        scopes,
        audience,
        expires_at: expiresAtIso,
        // Raw token shown ONCE — caller must persist it now.
        token: opaque.raw,
      });
    }

    // PAT branch
    const jti = crypto.randomUUID();
    const expSec = Math.floor(nowMs / 1000) + ttl;
    const pat = await generatePatJwt(
      { sub: userId, tenant: tenantId, aud: audience, scope: scopes, jti, exp: expSec },
      { signingSecret, issuer },
    );
    const refresh = await generateRefreshToken();
    const refreshExpiresIso = new Date(
      nowMs + DEFAULT_REFRESH_TTL_S * 1000,
    ).toISOString();

    const insertResp = await fetchImpl(`${env.supabaseUrl}/rest/v1/tokens`, {
      method: "POST",
      headers: { ...restHeaders, Prefer: "return=minimal" },
      body: JSON.stringify({
        id: tokenId,
        user_id: userId,
        tenant_id: tenantId,
        type: "pat",
        prefix: null,
        token_hash: null,
        jti,
        audience,
        scopes,
        name,
        expires_at: expiresAtIso,
      }),
    });
    if (!insertResp.ok) {
      return res.status(502).json({
        error: "Token insert failed",
        upstream_status: insertResp.status,
      });
    }

    const refreshResp = await fetchImpl(
      `${env.supabaseUrl}/rest/v1/refresh_tokens`,
      {
        method: "POST",
        headers: { ...restHeaders, Prefer: "return=minimal" },
        body: JSON.stringify({
          token_id: tokenId,
          hash: bytesToPgHex(refresh.hash),
          expires_at: refreshExpiresIso,
        }),
      },
    );
    if (!refreshResp.ok) {
      // Best-effort cleanup so the row doesn't stay un-rotatable.
      await fetchImpl(
        `${env.supabaseUrl}/rest/v1/tokens?id=eq.${tokenId}`,
        {
          method: "DELETE",
          headers: {
            apikey: env.serviceRoleKey,
            Authorization: `Bearer ${env.serviceRoleKey}`,
          },
        },
      ).catch(() => undefined);
      return res.status(502).json({
        error: "Refresh token insert failed",
        upstream_status: refreshResp.status,
      });
    }

    void emitAudit(
      { url: env.supabaseUrl, serviceRoleKey: env.serviceRoleKey },
      {
        eventType: "token.created",
        tenantId,
        actor: { type: "user", id: userId },
        data: {
          token_id: tokenId,
          type: "pat",
          name,
          scopes,
          audience,
          jti,
        },
      },
    );

    return res.status(201).json({
      id: tokenId,
      type: "pat",
      name,
      scopes,
      audience,
      expires_at: expiresAtIso,
      access_token: pat,
      refresh_token: refresh.raw,
      token_type: "Bearer",
      expires_in: ttl,
    });
  };
}

const defaultHandler = createCreateTokenHandler();
export default defaultHandler;
