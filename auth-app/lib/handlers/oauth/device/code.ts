/**
 * POST /api/oauth/device/code — RFC 8628 §3.1 device authorization request.
 *
 * The browserless device exchanges its `client_id` (and optional scope/audience)
 * for a `device_code` + `user_code`. The device polls the token endpoint with
 * `grant_type=urn:ietf:params:oauth:grant-type:device_code` while the user
 * approves the `user_code` on a separate device via `/oauth/device/verify`.
 *
 * Caller authentication: client_id only (no secret) — RFC 8628 leaves this to
 * the AS; we treat the client as a public client for the device flow because
 * the device cannot keep a secret. The `oauth_clients` row is still required
 * (revocation point + audience/scope allowlist).
 */

import type { VercelRequest, VercelResponse } from "../../_lib/types";
import {
  fetchOAuthClient,
  type OAuthClientRecord,
} from "../../_lib/oauth-client";

export interface DeviceCodeHandlerDeps {
  lookupClient?: (clientId: string) => Promise<OAuthClientRecord | null>;
  fetchImpl?: typeof fetch;
  now?: () => number;
  /** Test seam — override device_code generation. */
  generateDeviceCode?: () => string;
  /** Test seam — override user_code generation. */
  generateUserCode?: () => string;
}

interface ParsedBody {
  client_id?: string;
  scope?: string;
  audience?: string;
}

const DEVICE_CODE_RANDOM_BYTES = 43;
const USER_CODE_LENGTH = 8;
const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ23456789"; // 28 chars, no vowels/ambiguous
const DEVICE_CODE_TTL_S = 600;
const POLL_INTERVAL_S = 5;

function parseFormUrlEncoded(raw: string): ParsedBody {
  const params = new URLSearchParams(raw);
  const out: ParsedBody = {};
  const id = params.get("client_id");
  const scope = params.get("scope");
  const audience = params.get("audience");
  if (id) out.client_id = id;
  if (scope) out.scope = scope;
  if (audience) out.audience = audience;
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
      const j = JSON.parse(raw) as Record<string, unknown>;
      return {
        client_id: typeof j.client_id === "string" ? j.client_id : undefined,
        scope: typeof j.scope === "string" ? j.scope : undefined,
        audience: typeof j.audience === "string" ? j.audience : undefined,
      };
    } catch {
      return {};
    }
  }
  if (isPlainObject(raw)) {
    return {
      client_id:
        typeof raw.client_id === "string" ? raw.client_id : undefined,
      scope: typeof raw.scope === "string" ? raw.scope : undefined,
      audience: typeof raw.audience === "string" ? raw.audience : undefined,
    };
  }
  return {};
}

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function defaultGenerateDeviceCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(DEVICE_CODE_RANDOM_BYTES));
  return base64UrlEncode(bytes);
}

function defaultGenerateUserCode(): string {
  const random = crypto.getRandomValues(new Uint8Array(USER_CODE_LENGTH));
  let code = "";
  for (let i = 0; i < USER_CODE_LENGTH; i++) {
    code += USER_CODE_ALPHABET[random[i] % USER_CODE_ALPHABET.length];
  }
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

function oauthError(
  res: VercelResponse,
  status: number,
  error: string,
  description?: string,
): VercelResponse {
  return res
    .status(status)
    .json(description ? { error, error_description: description } : { error });
}

export function createDeviceCodeHandler(deps: DeviceCodeHandlerDeps = {}) {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const now = deps.now ?? Date.now;
  const generateDeviceCode =
    deps.generateDeviceCode ?? defaultGenerateDeviceCode;
  const generateUserCode = deps.generateUserCode ?? defaultGenerateUserCode;
  const lookupClient =
    deps.lookupClient ??
    ((id: string) => {
      const url = process.env.SUPABASE_URL;
      const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
      if (!url || !key) return Promise.resolve(null);
      return fetchOAuthClient({ url, serviceRoleKey: key }, id, fetchImpl);
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

    const body = readBody(req);
    if (!body.client_id) {
      return oauthError(res, 400, "invalid_request", "client_id is required");
    }

    const record = await lookupClient(body.client_id);
    if (!record || record.revoked_at !== null) {
      return oauthError(res, 401, "invalid_client");
    }

    const requestedScopes =
      typeof body.scope === "string" && body.scope.trim().length > 0
        ? body.scope.trim().split(/\s+/)
        : null;
    const allowedScopes = new Set(record.allowed_scopes);
    const scope = requestedScopes ?? record.allowed_scopes.slice();
    for (const s of scope) {
      if (!allowedScopes.has(s)) {
        return oauthError(
          res,
          400,
          "invalid_scope",
          `scope ${s} is not allowed for this client`,
        );
      }
    }

    const requestedAudiences =
      typeof body.audience === "string" && body.audience.trim().length > 0
        ? body.audience
            .split(/[\s,]+/)
            .map((a) => a.trim())
            .filter((a) => a.length > 0)
        : null;
    const allowedAudiences = new Set(record.allowed_audiences);
    const audience = requestedAudiences ?? record.allowed_audiences.slice();
    for (const a of audience) {
      if (!allowedAudiences.has(a)) {
        return oauthError(
          res,
          400,
          "invalid_target",
          `audience ${a} is not allowed for this client`,
        );
      }
    }

    const supabaseUrl = process.env.SUPABASE_URL;
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!supabaseUrl || !serviceRoleKey) {
      return res.status(500).json({ error: "Auth service not configured" });
    }

    const deviceCode = generateDeviceCode();
    const userCode = generateUserCode();
    const nowMs = now();
    const expiresAtIso = new Date(nowMs + DEVICE_CODE_TTL_S * 1000).toISOString();

    const insertResp = await fetchImpl(
      `${supabaseUrl}/rest/v1/device_codes`,
      {
        method: "POST",
        headers: {
          apikey: serviceRoleKey,
          Authorization: `Bearer ${serviceRoleKey}`,
          "Content-Type": "application/json",
          Prefer: "return=minimal",
        },
        body: JSON.stringify({
          device_code: deviceCode,
          user_code: userCode,
          client_id: body.client_id,
          scope,
          audience,
          user_id: null,
          status: "pending",
          expires_at: expiresAtIso,
        }),
      },
    );
    if (!insertResp.ok) {
      return res.status(502).json({
        error: "Device code insert failed",
        upstream_status: insertResp.status,
      });
    }

    const baseUrl = (
      process.env.AUTH_PUBLIC_BASE_URL ?? "https://auth.bsvibe.dev"
    ).replace(/\/$/, "");
    const verificationUri = `${baseUrl}/oauth/device/verify`;
    return res.status(200).json({
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: verificationUri,
      verification_uri_complete: `${verificationUri}?user_code=${userCode}`,
      expires_in: DEVICE_CODE_TTL_S,
      interval: POLL_INTERVAL_S,
    });
  };
}

const defaultHandler = createDeviceCodeHandler();
export default defaultHandler;
