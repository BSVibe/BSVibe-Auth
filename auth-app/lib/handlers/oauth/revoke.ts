/**
 * POST /oauth/revoke — RFC 7009 OAuth 2.0 Token Revocation.
 *
 * Body (form-urlencoded or JSON): { token, token_type_hint? }.
 *
 * Always 200 OK per RFC 7009 §2.2 — even if the token was unknown,
 * already revoked, or the type hint was wrong. This avoids the
 * confused-deputy trap where the response distinguishes "real" tokens
 * from synthetic ones.
 *
 * Auth: clients authenticate via Basic / POST credentials. Public
 * clients (PKCE-only) need only provide ``client_id``.
 *
 * Token type detection mirrors /api/tokens/introspect:
 *   - 3 JWT segments → decode jti, revoke tokens row by jti
 *   - 43-byte base64url (refresh_token shape) → look up refresh_tokens
 *     by sha256 hash, revoke parent token + sibling refresh rows
 *
 * (The legacy ``bsv_sk_*`` / ``bsv_pk_*`` opaque-by-token_hash branch was
 * retired in Tier 2 of the 2026-05 auth cleanup — issuance died in Tier 1,
 * dispatch died in bsvibe-authz 1.3.0, and the ``tokens.token_hash`` column
 * is dropped by the migration shipping with this PR.)
 */

import type { VercelRequest, VercelResponse } from "../_lib/types";
import {
  parseClientCredentials,
  fetchOAuthClient,
  verifyClientSecret,
} from "../_lib/oauth-client";
import { sha256Bytes, bytesToHex } from "../_lib/api-token";

interface ParsedBody {
  token?: string;
  token_type_hint?: string;
  client_id?: string;
  client_secret?: string;
}

const PARSED_KEYS = [
  "token",
  "token_type_hint",
  "client_id",
  "client_secret",
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

function readBody(req: VercelRequest): ParsedBody {
  const ct = String(req.headers["content-type"] ?? "").toLowerCase();
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
  if (raw && typeof raw === "object") {
    const out: ParsedBody = {};
    const r = raw as Record<string, unknown>;
    for (const k of PARSED_KEYS) {
      const v = r[k];
      if (typeof v === "string") out[k] = v;
    }
    return out;
  }
  return {};
}

function bytesToPgHex(b: Uint8Array): string {
  return `\\x${bytesToHex(b)}`;
}

interface RevokeContext {
  supabaseUrl: string;
  serviceRoleKey: string;
  fetchImpl: typeof fetch;
  nowIso: string;
}

async function revokeTokenById(
  ctx: RevokeContext,
  tokenId: string,
): Promise<void> {
  const headers = {
    apikey: ctx.serviceRoleKey,
    Authorization: `Bearer ${ctx.serviceRoleKey}`,
    "Content-Type": "application/json",
    Prefer: "return=minimal",
  } as const;
  const url = new URL(`${ctx.supabaseUrl}/rest/v1/tokens`);
  url.searchParams.set("id", `eq.${tokenId}`);
  url.searchParams.set("revoked_at", "is.null");
  await ctx
    .fetchImpl(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({ revoked_at: ctx.nowIso }),
    })
    .catch(() => undefined);
  // Invalidate every still-live sibling refresh row too.
  const refreshUrl = new URL(`${ctx.supabaseUrl}/rest/v1/refresh_tokens`);
  refreshUrl.searchParams.set("token_id", `eq.${tokenId}`);
  refreshUrl.searchParams.set("used_at", "is.null");
  await ctx
    .fetchImpl(refreshUrl.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({ used_at: ctx.nowIso }),
    })
    .catch(() => undefined);
}

async function revokeByJti(
  ctx: RevokeContext,
  jti: string,
): Promise<void> {
  const url = new URL(`${ctx.supabaseUrl}/rest/v1/tokens`);
  url.searchParams.set("select", "id");
  url.searchParams.set("jti", `eq.${jti}`);
  url.searchParams.set("limit", "1");
  const resp = await ctx
    .fetchImpl(url.toString(), {
      headers: {
        apikey: ctx.serviceRoleKey,
        Authorization: `Bearer ${ctx.serviceRoleKey}`,
        Accept: "application/json",
      },
    })
    .catch(() => null);
  if (!resp || !resp.ok) return;
  const rows = (await resp.json().catch(() => [])) as Array<{ id?: string }>;
  if (!Array.isArray(rows) || rows.length === 0) return;
  const id = rows[0].id;
  if (!id) return;
  await revokeTokenById(ctx, id);
}

async function revokeByRefreshHash(
  ctx: RevokeContext,
  rawRefresh: string,
): Promise<void> {
  const hashHex = bytesToPgHex(await sha256Bytes(rawRefresh));
  const url = new URL(`${ctx.supabaseUrl}/rest/v1/refresh_tokens`);
  url.searchParams.set("select", "token_id");
  url.searchParams.set("hash", `eq.${hashHex}`);
  url.searchParams.set("limit", "1");
  const resp = await ctx
    .fetchImpl(url.toString(), {
      headers: {
        apikey: ctx.serviceRoleKey,
        Authorization: `Bearer ${ctx.serviceRoleKey}`,
        Accept: "application/json",
      },
    })
    .catch(() => null);
  if (!resp || !resp.ok) return;
  const rows = (await resp.json().catch(() => [])) as Array<{
    token_id?: string;
  }>;
  if (!Array.isArray(rows) || rows.length === 0) return;
  const id = rows[0].token_id;
  if (!id) return;
  await revokeTokenById(ctx, id);
}

function looksLikeJwt(s: string): boolean {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(s);
}

function decodeJtiFromJwt(token: string): string | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const padded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padLen = (4 - (padded.length % 4)) % 4;
    const payload = JSON.parse(atob(padded + "=".repeat(padLen))) as {
      jti?: unknown;
    };
    return typeof payload.jti === "string" ? payload.jti : null;
  } catch {
    return null;
  }
}

export interface RevokeHandlerDeps {
  fetchImpl?: typeof fetch;
}

export function createRevokeHandler(deps: RevokeHandlerDeps = {}) {
  const fetchImpl = deps.fetchImpl ?? fetch;
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
      return res.status(405).json({ error: "method_not_allowed" });
    }

    const supabaseUrl = process.env.SUPABASE_URL;
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!supabaseUrl || !serviceRoleKey) {
      return res.status(500).json({ error: "server_error" });
    }

    const body = readBody(req);

    // Authenticate the client. Confidential clients must present a valid
    // secret; public clients (PKCE-only) just need a known client_id.
    const credentials = parseClientCredentials(req.headers.authorization, {
      client_id: body.client_id,
      client_secret: body.client_secret,
    });
    const clientId: string | null =
      credentials?.clientId ?? body.client_id ?? null;
    if (clientId) {
      const client = await fetchOAuthClient(
        { url: supabaseUrl, serviceRoleKey },
        clientId,
        fetchImpl,
      );
      if (!client || client.revoked_at !== null) {
        return res.status(401).json({ error: "invalid_client" });
      }
      if (client.client_type === "confidential") {
        if (!credentials) {
          return res.status(401).json({ error: "invalid_client" });
        }
        const ok = await verifyClientSecret(
          credentials.clientSecret,
          client.client_secret_hash,
        );
        if (!ok) {
          return res.status(401).json({ error: "invalid_client" });
        }
      }
    } else {
      // Anonymous revoke is disallowed; even public clients need to claim
      // a client_id so audit trails can attribute the action.
      return res.status(401).json({ error: "invalid_client" });
    }

    const token = body.token;
    if (!token) {
      // RFC 7009 §2.2 says respond 200 OK even on malformed input.
      return res.status(200).json({});
    }

    const ctx: RevokeContext = {
      supabaseUrl,
      serviceRoleKey,
      fetchImpl,
      nowIso: new Date().toISOString(),
    };

    if (looksLikeJwt(token)) {
      const jti = decodeJtiFromJwt(token);
      if (jti) await revokeByJti(ctx, jti);
    } else {
      // Treat anything else as a refresh_token candidate. (The legacy
      // ``bsv_sk_*`` / ``bsv_pk_*`` opaque branch was retired in Tier 2.)
      await revokeByRefreshHash(ctx, token);
    }

    return res.status(200).json({});
  };
}

const defaultHandler = createRevokeHandler();
export default defaultHandler;
