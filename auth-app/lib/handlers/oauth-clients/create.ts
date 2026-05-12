/**
 * POST /api/oauth/clients — create a confidential service-account
 * oauth_client for the caller's primary tenant.
 *
 * Auth: Supabase user JWT (same surface as /api/tokens). The caller
 * must belong to at least one tenant; the new client_secret is bound
 * to that tenant.
 *
 * Body: { name, allowed_audiences[], allowed_scopes[] }.
 *
 * Response (201): { client_id, client_secret, ... } — the plain
 * client_secret is shown ONCE and never persisted. PBKDF2-hashed at
 * rest.
 */

import type { VercelRequest, VercelResponse } from "../_lib/types";
import { hashClientSecret } from "../_lib/oauth-client";
import {
  emitAuditEventBestEffort,
  type AuditEmitInput,
} from "../_lib/audit-emit";
import {
  authenticate,
  handleCorsAndMethod,
  verifySupabaseAccessToken,
  type VerifyAccessTokenFn,
} from "../api-tokens/_auth";
import {
  generateClientId,
  generateClientSecret,
  isAllowedAudience,
  isValidScope,
  resolvePrimaryTenantId,
} from "./_shared";

interface CreateBody {
  name?: unknown;
  allowed_audiences?: unknown;
  allowed_scopes?: unknown;
}

const NAME_MAX = 128;
const SCOPE_MAX = 64;
const AUDIENCES_MAX = 8;
const SCOPES_MAX = 32;

export interface CreateOAuthClientHandlerDeps {
  verifyAccessToken?: VerifyAccessTokenFn;
  fetchImpl?: typeof fetch;
  emitAudit?: (input: AuditEmitInput) => Promise<void>;
  resolveTenantId?: (userId: string) => Promise<string | null>;
  generateClientId?: () => string;
  generateClientSecret?: () => string;
}

function parseBody(req: VercelRequest): CreateBody {
  const raw = req.body;
  if (typeof raw === "string") {
    try {
      return JSON.parse(raw) as CreateBody;
    } catch {
      return {};
    }
  }
  if (raw && typeof raw === "object") return raw as CreateBody;
  return {};
}

export function createOAuthClientHandler(
  deps: CreateOAuthClientHandlerDeps = {},
) {
  const verifyAccessToken = deps.verifyAccessToken ?? verifySupabaseAccessToken;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const emitAudit =
    deps.emitAudit ??
    (async (input: AuditEmitInput) => {
      const url = process.env.SUPABASE_URL;
      const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
      if (!url || !key) return;
      await emitAuditEventBestEffort(
        { url, serviceRoleKey: key },
        input,
        { fetchImpl },
      );
    });
  const mintClientId = deps.generateClientId ?? generateClientId;
  const mintClientSecret = deps.generateClientSecret ?? generateClientSecret;

  return async function handler(req: VercelRequest, res: VercelResponse) {
    if (handleCorsAndMethod(req, res, "POST")) return;

    const auth = await authenticate(req, res, verifyAccessToken, fetchImpl);
    if (!auth) return;
    const { userId, env } = auth;

    const body = parseBody(req);

    const name =
      typeof body.name === "string" ? body.name.trim() : "";
    if (!name || name.length > NAME_MAX) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: `name is required (max ${NAME_MAX} chars)`,
      });
    }

    if (!Array.isArray(body.allowed_audiences) || body.allowed_audiences.length === 0) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "allowed_audiences is required (non-empty array)",
      });
    }
    if (body.allowed_audiences.length > AUDIENCES_MAX) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: `allowed_audiences exceeds limit of ${AUDIENCES_MAX}`,
      });
    }
    for (const a of body.allowed_audiences) {
      if (!isAllowedAudience(a)) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: `unknown audience: ${a}`,
        });
      }
    }
    const allowedAudiences = body.allowed_audiences as string[];

    if (!Array.isArray(body.allowed_scopes) || body.allowed_scopes.length === 0) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "allowed_scopes is required (non-empty array)",
      });
    }
    if (body.allowed_scopes.length > SCOPES_MAX) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: `allowed_scopes exceeds limit of ${SCOPES_MAX}`,
      });
    }
    for (const s of body.allowed_scopes) {
      if (!isValidScope(s) || (typeof s === "string" && s.length > SCOPE_MAX)) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: `invalid scope: ${String(s)}`,
        });
      }
    }
    const allowedScopes = body.allowed_scopes as string[];

    const tenantResolver =
      deps.resolveTenantId ??
      ((id: string) =>
        resolvePrimaryTenantId(
          fetchImpl,
          env.supabaseUrl,
          env.serviceRoleKey,
          id,
        ));
    const tenantId = await tenantResolver(userId);
    if (!tenantId) {
      return res.status(403).json({
        error: "no_tenant_membership",
        error_description:
          "user must belong to at least one tenant before creating a service account",
      });
    }

    const clientId = mintClientId();
    const rawSecret = mintClientSecret();
    const secretHash = await hashClientSecret(rawSecret);

    const insertResp = await fetchImpl(
      `${env.supabaseUrl.replace(/\/$/, "")}/rest/v1/oauth_clients`,
      {
        method: "POST",
        headers: {
          apikey: env.serviceRoleKey,
          Authorization: `Bearer ${env.serviceRoleKey}`,
          "Content-Type": "application/json",
          Prefer: "return=representation",
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret_hash: secretHash,
          client_type: "confidential",
          tenant_id: tenantId,
          description: name,
          allowed_audiences: allowedAudiences,
          allowed_scopes: allowedScopes,
        }),
      },
    );
    if (!insertResp.ok) {
      const detail = await insertResp.text().catch(() => "");
      return res.status(502).json({
        error: "server_error",
        error_description: `client persistence failed: ${insertResp.status} ${detail.slice(0, 200)}`,
      });
    }
    const rows = (await insertResp
      .json()
      .catch(() => null)) as Array<{
      client_id: string;
      description: string | null;
      tenant_id: string;
      allowed_audiences: string[];
      allowed_scopes: string[];
      created_at: string;
    }> | null;
    const row = Array.isArray(rows) ? rows[0] : null;

    void emitAudit({
      eventType: "oauth_client.created",
      tenantId,
      actor: { type: "user", id: userId },
      data: {
        client_id: clientId,
        client_type: "confidential",
        allowed_audiences: allowedAudiences,
        allowed_scopes: allowedScopes,
      },
    });

    return res.status(201).json({
      client_id: clientId,
      client_secret: rawSecret,
      client_type: "confidential",
      tenant_id: tenantId,
      name,
      allowed_audiences: allowedAudiences,
      allowed_scopes: allowedScopes,
      created_at: row?.created_at ?? new Date().toISOString(),
      token_endpoint: `${process.env.SERVICE_TOKEN_ISSUER ?? "https://auth.bsvibe.dev"}/oauth/token`,
    });
  };
}

const defaultHandler = createOAuthClientHandler();
export default defaultHandler;
