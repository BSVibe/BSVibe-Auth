/**
 * DELETE /api/oauth/clients/:id — revoke a service-account oauth_client.
 *
 * Soft-delete via ``revoked_at = now()``. Idempotent — re-DELETE
 * returns 200 with ``already_revoked: true``. Scoped to the caller's
 * primary tenant so cross-tenant revocation is blocked.
 */

import type { VercelRequest, VercelResponse } from "../_lib/types";
import {
  emitAuditEventBestEffort,
  type AuditEmitInput,
} from "../_lib/audit-emit";
import {
  authenticate,
  handleCorsAndMethod,
  supabaseServiceHeaders,
  verifySupabaseAccessToken,
  type VerifyAccessTokenFn,
} from "../api-tokens/_auth";
import {
  CLIENT_ID_PATTERN,
  getClientIdFromRequest,
  resolvePrimaryTenantId,
} from "./_shared";

export interface RevokeOAuthClientHandlerDeps {
  verifyAccessToken?: VerifyAccessTokenFn;
  fetchImpl?: typeof fetch;
  emitAudit?: (input: AuditEmitInput) => Promise<void>;
  resolveTenantId?: (userId: string) => Promise<string | null>;
  now?: () => number;
}

interface ExistingRow {
  client_id: string;
  tenant_id: string | null;
  client_type: string;
  revoked_at: string | null;
}

export function createRevokeOAuthClientHandler(
  deps: RevokeOAuthClientHandlerDeps = {},
) {
  const verifyAccessToken = deps.verifyAccessToken ?? verifySupabaseAccessToken;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const now = deps.now ?? Date.now;
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

  return async function handler(req: VercelRequest, res: VercelResponse) {
    if (handleCorsAndMethod(req, res, "DELETE")) return;
    const auth = await authenticate(req, res, verifyAccessToken, fetchImpl);
    if (!auth) return;
    const { userId, env } = auth;

    const clientId = getClientIdFromRequest(req);
    if (!clientId || !CLIENT_ID_PATTERN.test(clientId)) {
      return res
        .status(400)
        .json({ error: "invalid_request", error_description: "client_id is required" });
    }

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
      return res.status(403).json({ error: "no_tenant_membership" });
    }

    // Lookup — scoped to caller's tenant to block cross-tenant revoke.
    const lookupUrl = new URL(`${env.supabaseUrl}/rest/v1/oauth_clients`);
    lookupUrl.searchParams.set(
      "select",
      "client_id,tenant_id,client_type,revoked_at",
    );
    lookupUrl.searchParams.set("client_id", `eq.${clientId}`);
    lookupUrl.searchParams.set("tenant_id", `eq.${tenantId}`);
    lookupUrl.searchParams.set("limit", "1");
    const lookupResp = await fetchImpl(lookupUrl.toString(), {
      headers: supabaseServiceHeaders(env),
    });
    if (!lookupResp.ok) {
      return res
        .status(502)
        .json({ error: "lookup_failed", upstream_status: lookupResp.status });
    }
    const rows = (await lookupResp.json()) as ExistingRow[];
    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(404).json({ error: "not_found" });
    }
    const row = rows[0];
    if (row.revoked_at !== null) {
      return res.status(200).json({ already_revoked: true, client_id: clientId });
    }

    const nowIso = new Date(now()).toISOString();
    const patchUrl = new URL(`${env.supabaseUrl}/rest/v1/oauth_clients`);
    patchUrl.searchParams.set("client_id", `eq.${clientId}`);
    patchUrl.searchParams.set("tenant_id", `eq.${tenantId}`);
    patchUrl.searchParams.set("revoked_at", "is.null");
    const patchResp = await fetchImpl(patchUrl.toString(), {
      method: "PATCH",
      headers: {
        ...supabaseServiceHeaders(env),
        "Content-Type": "application/json",
        Prefer: "return=minimal",
      },
      body: JSON.stringify({ revoked_at: nowIso }),
    });
    if (!patchResp.ok) {
      return res
        .status(502)
        .json({ error: "revoke_failed", upstream_status: patchResp.status });
    }

    void emitAudit({
      eventType: "oauth_client.revoked",
      tenantId,
      actor: { type: "user", id: userId },
      data: { client_id: clientId },
    });

    return res.status(200).json({ revoked: true, client_id: clientId });
  };
}

const defaultHandler = createRevokeOAuthClientHandler();
export default defaultHandler;
