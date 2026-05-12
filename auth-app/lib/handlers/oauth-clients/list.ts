/**
 * GET /api/oauth/clients — list service-account oauth_clients for the
 * caller's primary tenant.
 *
 * Returns metadata only — never includes client_secret_hash. Scoped to
 * the caller's primary tenant so cross-tenant enumeration is blocked.
 */

import type { VercelRequest, VercelResponse } from "../_lib/types";
import {
  authenticate,
  handleCorsAndMethod,
  supabaseServiceHeaders,
  verifySupabaseAccessToken,
  type VerifyAccessTokenFn,
} from "../api-tokens/_auth";
import {
  OAUTH_CLIENT_METADATA_SELECT,
  resolvePrimaryTenantId,
} from "./_shared";

export interface ListOAuthClientsHandlerDeps {
  verifyAccessToken?: VerifyAccessTokenFn;
  fetchImpl?: typeof fetch;
  resolveTenantId?: (userId: string) => Promise<string | null>;
}

export function createListOAuthClientsHandler(
  deps: ListOAuthClientsHandlerDeps = {},
) {
  const verifyAccessToken = deps.verifyAccessToken ?? verifySupabaseAccessToken;
  const fetchImpl = deps.fetchImpl ?? fetch;

  return async function handler(req: VercelRequest, res: VercelResponse) {
    if (handleCorsAndMethod(req, res, "GET")) return;
    const auth = await authenticate(req, res, verifyAccessToken, fetchImpl);
    if (!auth) return;
    const { userId, env } = auth;

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
      return res.status(200).json({ clients: [] });
    }

    const url = new URL(`${env.supabaseUrl}/rest/v1/oauth_clients`);
    url.searchParams.set("select", OAUTH_CLIENT_METADATA_SELECT);
    url.searchParams.set("tenant_id", `eq.${tenantId}`);
    url.searchParams.set("client_type", "eq.confidential");
    url.searchParams.set("order", "created_at.desc");

    const resp = await fetchImpl(url.toString(), {
      headers: supabaseServiceHeaders(env),
    });
    if (!resp.ok) {
      return res
        .status(502)
        .json({ error: "list_failed", upstream_status: resp.status });
    }
    const clients = (await resp.json()) as unknown[];
    return res.status(200).json({ clients });
  };
}

const defaultHandler = createListOAuthClientsHandler();
export default defaultHandler;
