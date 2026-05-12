/**
 * RFC 7591 OAuth 2.0 Dynamic Client Registration (DCR).
 *
 * Open registration for *public* clients only — anyone can POST a
 * client_name + redirect_uris and receive back a client_id with no
 * secret. Confidential clients (with client_secret_hash) are still
 * provisioned out-of-band by the operator; DCR is purely the
 * Claude-Desktop-style "first time on this device" path.
 *
 * Constraints:
 *  - redirect_uris must be loopback (RFC 8252 §7.3) OR a small set of
 *    pre-approved hosts (Claude Code's claude://oauth, vscode://,
 *    etc.). Open-redirect is the canonical DCR footgun and we don't
 *    need the flexibility.
 *  - allowed_scopes default to the union of BSVibe MCP scopes — the
 *    /authorize endpoint enforces actual scope grants. DCR can't
 *    over-grant.
 *  - allowed_audiences default to all 4 products.
 */

import type { VercelRequest, VercelResponse } from "../_lib/types";

const ALLOWED_LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
const ALLOWED_CUSTOM_SCHEMES = new Set([
  "claude",
  "vscode",
  "vscode-insiders",
  "cursor",
]);
const DEFAULT_SCOPES = ["gateway:*", "sage:*", "nexus:*", "supervisor:*"];
const DEFAULT_AUDIENCES = ["gateway", "sage", "nexus", "supervisor"];

interface RegisterBody {
  client_name?: string;
  redirect_uris?: string[];
  scope?: string;
  audience?: string;
}

function validateRedirectUri(uri: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }
  if (parsed.protocol === "http:") {
    return ALLOWED_LOOPBACK_HOSTS.has(parsed.hostname);
  }
  if (parsed.protocol === "https:") {
    // Tight allow-list — only public BSVibe-owned redirect host.
    return parsed.hostname === "auth.bsvibe.dev";
  }
  // Custom-scheme (claude://, vscode://, …). RFC 8252 §7.1.
  const scheme = parsed.protocol.replace(/:$/, "");
  return ALLOWED_CUSTOM_SCHEMES.has(scheme);
}

function parseBody(req: VercelRequest): RegisterBody {
  const raw = req.body;
  if (typeof raw === "string") {
    try {
      return JSON.parse(raw) as RegisterBody;
    } catch {
      return {};
    }
  }
  if (raw && typeof raw === "object") return raw as RegisterBody;
  return {};
}

function randomSuffix(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

export interface RegisterHandlerDeps {
  fetchImpl?: typeof fetch;
}

export function createRegisterHandler(deps: RegisterHandlerDeps = {}) {
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
      return res
        .status(500)
        .json({ error: "server_error", error_description: "auth service not configured" });
    }

    const body = parseBody(req);
    if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0) {
      return res
        .status(400)
        .json({ error: "invalid_redirect_uri", error_description: "redirect_uris is required" });
    }
    for (const uri of body.redirect_uris) {
      if (typeof uri !== "string" || !validateRedirectUri(uri)) {
        return res.status(400).json({
          error: "invalid_redirect_uri",
          error_description: `redirect_uri not allowed: ${uri}`,
        });
      }
    }

    const clientName =
      typeof body.client_name === "string" && body.client_name.length > 0
        ? body.client_name.slice(0, 128)
        : "dynamic-client";
    let scope =
      typeof body.scope === "string" && body.scope.trim().length > 0
        ? body.scope
            .trim()
            .split(/\s+/)
            .filter(
              (s) =>
                DEFAULT_SCOPES.includes(s) || isScopePrefixOf(DEFAULT_SCOPES, s),
            )
        : DEFAULT_SCOPES.slice();
    if (scope.length === 0) scope = DEFAULT_SCOPES.slice();
    let audience =
      typeof body.audience === "string" && body.audience.trim().length > 0
        ? body.audience
            .split(",")
            .map((a) => a.trim())
            .filter((a) => DEFAULT_AUDIENCES.includes(a))
        : DEFAULT_AUDIENCES.slice();
    if (audience.length === 0) audience = DEFAULT_AUDIENCES.slice();

    const clientId = `dcr-${randomSuffix()}`;
    const insertResp = await fetchImpl(
      `${supabaseUrl.replace(/\/$/, "")}/rest/v1/oauth_clients`,
      {
        method: "POST",
        headers: {
          apikey: serviceRoleKey,
          Authorization: `Bearer ${serviceRoleKey}`,
          "Content-Type": "application/json",
          Prefer: "return=minimal",
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret_hash: null,
          client_type: "public",
          tenant_id: null,
          allowed_scopes: scope,
          allowed_audiences: audience,
          redirect_uris: body.redirect_uris,
          description: clientName,
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

    return res.status(201).json({
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: clientName,
      redirect_uris: body.redirect_uris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: scope.join(" "),
    });
  };
}

function isScopePrefixOf(allowed: string[], requested: string): boolean {
  for (const a of allowed) {
    if (a.endsWith(":*") && requested.startsWith(a.slice(0, -1))) return true;
  }
  return false;
}

const defaultHandler = createRegisterHandler();
export default defaultHandler;
