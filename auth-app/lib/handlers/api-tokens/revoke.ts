/**
 * DELETE /api/tokens/:id — revoke a single token.
 *
 * Soft delete via `revoked_at = now()`. Idempotent: a second DELETE returns
 * 200 with `already_revoked: true` rather than mutating again. Lookup +
 * PATCH are scoped by both id and user_id so cross-user revocation is
 * impossible. token.revoked is emitted only on the state-changing path.
 */

import type { VercelRequest, VercelResponse } from "../_lib/types";
import {
  emitAuditEventBestEffort,
  type AuditEmitInput,
  type AuditEmitResult,
} from "../_lib/audit-emit";
import {
  authenticate,
  getTokenIdFromRequest,
  isUuid,
  verifySupabaseAccessToken,
  type VerifyAccessTokenFn,
} from "./_auth";

export type EmitAuditFn = (
  cfg: { url: string; serviceRoleKey: string },
  input: AuditEmitInput,
) => Promise<AuditEmitResult>;

export interface RevokeTokenHandlerDeps {
  verifyAccessToken?: VerifyAccessTokenFn;
  fetchImpl?: typeof fetch;
  emitAudit?: EmitAuditFn;
  now?: () => number;
}

interface ExistingRow {
  id: string;
  tenant_id: string;
  type: "pat" | "api_key";
  revoked_at: string | null;
}

export function createRevokeTokenHandler(deps: RevokeTokenHandlerDeps = {}) {
  const verifyAccessToken = deps.verifyAccessToken ?? verifySupabaseAccessToken;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const emitAudit: EmitAuditFn =
    deps.emitAudit ??
    ((cfg, input) => emitAuditEventBestEffort(cfg, input, { fetchImpl }));
  const now = deps.now ?? Date.now;

  return async function handler(req: VercelRequest, res: VercelResponse) {
    if (req.method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "DELETE, OPTIONS");
      res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization",
      );
      return res.status(204).end();
    }
    if (req.method !== "DELETE") {
      return res.status(405).json({ error: "Method not allowed" });
    }

    const auth = await authenticate(req, res, verifyAccessToken, fetchImpl);
    if (!auth) return;
    const { userId, env } = auth;

    const id = getTokenIdFromRequest(req);
    if (!isUuid(id)) {
      return res.status(400).json({ error: "id must be a uuid" });
    }

    const restHeaders = {
      apikey: env.serviceRoleKey,
      Authorization: `Bearer ${env.serviceRoleKey}`,
      Accept: "application/json",
    } as const;

    // Lookup — both filters mean a row from another user reads as "not found".
    const lookupUrl = new URL(`${env.supabaseUrl}/rest/v1/tokens`);
    lookupUrl.searchParams.set("select", "id,tenant_id,type,revoked_at");
    lookupUrl.searchParams.set("user_id", `eq.${userId}`);
    lookupUrl.searchParams.set("id", `eq.${id}`);
    lookupUrl.searchParams.set("limit", "1");

    const lookupResp = await fetchImpl(lookupUrl.toString(), {
      headers: restHeaders,
    });
    if (!lookupResp.ok) {
      return res
        .status(502)
        .json({ error: "Token lookup failed", upstream_status: lookupResp.status });
    }
    const rows = (await lookupResp.json()) as ExistingRow[];
    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(404).json({ error: "Token not found" });
    }
    const existing = rows[0];
    if (existing.revoked_at) {
      return res.status(200).json({
        id: existing.id,
        already_revoked: true,
        revoked_at: existing.revoked_at,
      });
    }

    const revokedAt = new Date(now()).toISOString();
    const patchUrl = new URL(`${env.supabaseUrl}/rest/v1/tokens`);
    patchUrl.searchParams.set("user_id", `eq.${userId}`);
    patchUrl.searchParams.set("id", `eq.${id}`);
    patchUrl.searchParams.set("revoked_at", "is.null");

    const patchResp = await fetchImpl(patchUrl.toString(), {
      method: "PATCH",
      headers: {
        ...restHeaders,
        "Content-Type": "application/json",
        Prefer: "return=representation",
      },
      body: JSON.stringify({ revoked_at: revokedAt }),
    });
    if (!patchResp.ok) {
      return res
        .status(502)
        .json({ error: "Token revoke failed", upstream_status: patchResp.status });
    }

    void emitAudit(
      { url: env.supabaseUrl, serviceRoleKey: env.serviceRoleKey },
      {
        eventType: "token.revoked",
        tenantId: existing.tenant_id,
        actor: { type: "user", id: userId },
        data: {
          token_id: existing.id,
          type: existing.type,
        },
      },
    );

    return res.status(200).json({
      id: existing.id,
      revoked_at: revokedAt,
      already_revoked: false,
    });
  };
}

const defaultHandler = createRevokeTokenHandler();
export default defaultHandler;
