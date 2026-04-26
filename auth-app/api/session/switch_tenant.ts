import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  getMembership as getMembershipImpl,
  type SupabaseConfig,
  type TenantRole,
} from "../_lib/tenants";

const ACTIVE_TENANT_COOKIE = "bsvibe_active_tenant";
const COOKIE_DOMAIN = ".bsvibe.dev";
const COOKIE_MAX_AGE = 30 * 24 * 60 * 60; // 30 days

export interface SwitchTenantHandlerDeps {
  getMembership?: (
    cfg: SupabaseConfig,
    userId: string,
    tenantId: string,
    fetchImpl?: typeof fetch,
  ) => Promise<TenantRole | null>;
  fetchImpl?: typeof fetch;
}

interface AccessTokenPayload {
  sub?: string;
}

function decodeUserId(token: string): string | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const padded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padLen = (4 - (padded.length % 4)) % 4;
    const payload = JSON.parse(
      atob(padded + "=".repeat(padLen)),
    ) as AccessTokenPayload;
    return payload.sub ?? null;
  } catch {
    return null;
  }
}

export function createSwitchTenantHandler(
  deps: SwitchTenantHandlerDeps = {},
) {
  const getMembership = deps.getMembership ?? getMembershipImpl;
  const fetchImpl = deps.fetchImpl ?? fetch;

  return async function handler(req: VercelRequest, res: VercelResponse) {
    if (req.method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
      return res.status(204).end();
    }

    if (req.method !== "POST") {
      return res.status(405).json({ error: "Method not allowed" });
    }

    const supabaseUrl = process.env.SUPABASE_URL;
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!supabaseUrl || !serviceRoleKey) {
      return res.status(500).json({ error: "Auth service not configured" });
    }

    const authHeader = req.headers.authorization ?? "";
    const accessToken = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!accessToken) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    const userId = decodeUserId(accessToken);
    if (!userId) {
      return res.status(401).json({ error: "Invalid access_token" });
    }

    const { tenant_id } = (req.body ?? {}) as { tenant_id?: unknown };
    if (typeof tenant_id !== "string" || tenant_id.length === 0) {
      return res.status(400).json({ error: "tenant_id is required" });
    }

    const role = await getMembership(
      { url: supabaseUrl, serviceRoleKey },
      userId,
      tenant_id,
      fetchImpl,
    );

    if (!role) {
      return res
        .status(403)
        .json({ error: "Not a member of the requested tenant" });
    }

    // Persist the user's active tenant choice as a long-lived cookie so the
    // next /api/session GET picks it up via pickActiveTenant().
    res.setHeader(
      "Set-Cookie",
      `${ACTIVE_TENANT_COOKIE}=${tenant_id}; HttpOnly; Secure; SameSite=Lax; Domain=${COOKIE_DOMAIN}; Path=/; Max-Age=${COOKIE_MAX_AGE}`,
    );

    return res.status(200).json({ active_tenant_id: tenant_id, role });
  };
}

const defaultHandler = createSwitchTenantHandler();
export default defaultHandler;
