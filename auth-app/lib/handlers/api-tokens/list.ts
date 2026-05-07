/**
 * GET /api/tokens — list the caller's tokens.
 *
 * Returns metadata only — never includes token_hash or jti. Optional ?type
 * filter constrained to 'pat' | 'api_key'. RLS plus an explicit user_id
 * filter (we run via service-role) ensures cross-user isolation.
 */

import type { VercelRequest, VercelResponse } from "../_lib/types";
import {
  authenticate,
  METADATA_SELECT,
  verifySupabaseAccessToken,
  type VerifyAccessTokenFn,
} from "./_auth";

export interface ListTokensHandlerDeps {
  verifyAccessToken?: VerifyAccessTokenFn;
  fetchImpl?: typeof fetch;
}

const ALLOWED_TYPES: ReadonlySet<string> = new Set(["pat", "api_key"]);

export function createListTokensHandler(deps: ListTokensHandlerDeps = {}) {
  const verifyAccessToken = deps.verifyAccessToken ?? verifySupabaseAccessToken;
  const fetchImpl = deps.fetchImpl ?? fetch;

  return async function handler(req: VercelRequest, res: VercelResponse) {
    if (req.method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
      res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization",
      );
      return res.status(204).end();
    }
    if (req.method !== "GET") {
      return res.status(405).json({ error: "Method not allowed" });
    }
    const auth = await authenticate(req, res, verifyAccessToken, fetchImpl);
    if (!auth) return;
    const { userId, env } = auth;

    const typeFilter = req.query?.type;
    if (typeFilter !== undefined) {
      if (typeof typeFilter !== "string" || !ALLOWED_TYPES.has(typeFilter)) {
        return res
          .status(400)
          .json({ error: "type must be 'pat' or 'api_key'" });
      }
    }

    const url = new URL(`${env.supabaseUrl}/rest/v1/tokens`);
    url.searchParams.set("select", METADATA_SELECT);
    url.searchParams.set("user_id", `eq.${userId}`);
    url.searchParams.set("order", "created_at.desc");
    if (typeFilter) url.searchParams.set("type", `eq.${typeFilter}`);

    const resp = await fetchImpl(url.toString(), {
      headers: {
        apikey: env.serviceRoleKey,
        Authorization: `Bearer ${env.serviceRoleKey}`,
        Accept: "application/json",
      },
    });
    if (!resp.ok) {
      return res
        .status(502)
        .json({ error: "Token list failed", upstream_status: resp.status });
    }
    const tokens = (await resp.json()) as unknown[];
    return res.status(200).json({ tokens });
  };
}

const defaultHandler = createListTokensHandler();
export default defaultHandler;
