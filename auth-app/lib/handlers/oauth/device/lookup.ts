/**
 * GET /api/oauth/device/lookup?user_code=XXXX-XXXX
 *
 * Read-only lookup so the verify UI can show the user *what* a device is
 * requesting before they approve. Without this, the user would only see the
 * matching `user_code` (RFC 8628 §3.3 / §5.4 best practice is to display the
 * scope/audience too so the user can spot a malicious device asking for more
 * than expected).
 *
 * Authenticated identically to /api/oauth/device/verify (Supabase Bearer).
 * Returns 404 for any non-pending or expired row so callers can't enumerate
 * past device codes.
 */

import type { VercelRequest, VercelResponse } from "../../_lib/types";
import {
  authenticate,
  verifySupabaseAccessToken,
  type VerifyAccessTokenFn,
} from "../../api-tokens/_auth";

export interface DeviceLookupHandlerDeps {
  verifyAccessToken?: VerifyAccessTokenFn;
  fetchImpl?: typeof fetch;
}

const USER_CODE_PATTERN = /^[A-Z0-9]{4}-[A-Z0-9]{4}$/;

interface DeviceCodeRow {
  user_code: string;
  client_id: string | null;
  scope: unknown;
  audience: unknown;
  expires_at: string;
  status: string;
}

function asStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string");
}

export function createDeviceLookupHandler(deps: DeviceLookupHandlerDeps = {}) {
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
    const { env } = auth;

    const rawUserCode = req.query?.user_code;
    const userCode =
      typeof rawUserCode === "string" ? rawUserCode.toUpperCase() : "";
    if (!USER_CODE_PATTERN.test(userCode)) {
      return res.status(400).json({ error: "user_code must match XXXX-XXXX" });
    }

    const nowIso = new Date().toISOString();
    const url = new URL(`${env.supabaseUrl}/rest/v1/device_codes`);
    url.searchParams.set(
      "select",
      "user_code,client_id,scope,audience,expires_at,status",
    );
    url.searchParams.set("user_code", `eq.${userCode}`);
    url.searchParams.set("status", "eq.pending");
    url.searchParams.set("expires_at", `gt.${nowIso}`);
    url.searchParams.set("limit", "1");

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
        .json({ error: "Device lookup failed", upstream_status: resp.status });
    }
    const rows = (await resp.json()) as DeviceCodeRow[];
    if (!Array.isArray(rows) || rows.length === 0) {
      return res
        .status(404)
        .json({ error: "user_code not found, expired, or already verified" });
    }
    const row = rows[0];
    return res.status(200).json({
      user_code: row.user_code,
      client_id: row.client_id ?? null,
      scope: asStringArray(row.scope),
      audience: asStringArray(row.audience),
      expires_at: row.expires_at,
    });
  };
}

const defaultHandler = createDeviceLookupHandler();
export default defaultHandler;
