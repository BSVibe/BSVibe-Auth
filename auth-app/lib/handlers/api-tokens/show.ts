/**
 * GET /api/tokens/:id — return metadata for a single token.
 *
 * Token is identified by `id` (UUID). Filter is double-bound: `user_id` plus
 * `id` so a user can never enumerate a row that isn't theirs (404 for both
 * "not found" and "found but not yours" — by design).
 */

import type { VercelRequest, VercelResponse } from "../_lib/types";
import {
  authenticate,
  getTokenIdFromRequest,
  handleCorsAndMethod,
  isUuid,
  METADATA_SELECT,
  supabaseServiceHeaders,
  verifySupabaseAccessToken,
  type VerifyAccessTokenFn,
} from "./_auth";

export interface ShowTokenHandlerDeps {
  verifyAccessToken?: VerifyAccessTokenFn;
  fetchImpl?: typeof fetch;
}

export function createShowTokenHandler(deps: ShowTokenHandlerDeps = {}) {
  const verifyAccessToken = deps.verifyAccessToken ?? verifySupabaseAccessToken;
  const fetchImpl = deps.fetchImpl ?? fetch;

  return async function handler(req: VercelRequest, res: VercelResponse) {
    if (handleCorsAndMethod(req, res, "GET")) return;

    const auth = await authenticate(req, res, verifyAccessToken, fetchImpl);
    if (!auth) return;
    const { userId, env } = auth;

    const id = getTokenIdFromRequest(req);
    if (!isUuid(id)) {
      return res.status(400).json({ error: "id must be a uuid" });
    }

    const url = new URL(`${env.supabaseUrl}/rest/v1/tokens`);
    url.searchParams.set("select", METADATA_SELECT);
    url.searchParams.set("user_id", `eq.${userId}`);
    url.searchParams.set("id", `eq.${id}`);
    url.searchParams.set("limit", "1");

    const resp = await fetchImpl(url.toString(), {
      headers: supabaseServiceHeaders(env),
    });
    if (!resp.ok) {
      return res
        .status(502)
        .json({ error: "Token lookup failed", upstream_status: resp.status });
    }
    const rows = (await resp.json()) as unknown[];
    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(404).json({ error: "Token not found" });
    }
    return res.status(200).json({ token: rows[0] });
  };
}

const defaultHandler = createShowTokenHandler();
export default defaultHandler;
