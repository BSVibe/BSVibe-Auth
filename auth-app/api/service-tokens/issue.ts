import type { VercelRequest, VercelResponse } from "@vercel/node";
import {
  getMembership as getMembershipImpl,
  type SupabaseConfig,
  type TenantRole,
} from "../_lib/tenants";
import {
  issueServiceToken,
  ServiceTokenError,
  type ServiceAudience,
} from "../_lib/service-token";

export interface IssueServiceTokenHandlerDeps {
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

const ELEVATED_ROLES: ReadonlySet<TenantRole> = new Set(["owner", "admin"]);

export function createIssueServiceTokenHandler(
  deps: IssueServiceTokenHandlerDeps = {},
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
    const signingSecret = process.env.SERVICE_TOKEN_SIGNING_SECRET;
    const issuer =
      process.env.SERVICE_TOKEN_ISSUER || "https://auth.bsvibe.dev";

    if (!supabaseUrl || !serviceRoleKey) {
      return res.status(500).json({ error: "Auth service not configured" });
    }
    if (!signingSecret) {
      return res
        .status(500)
        .json({ error: "Service token signing secret not configured" });
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

    const body = (req.body ?? {}) as {
      audience?: unknown;
      scope?: unknown;
      tenant_id?: unknown;
      ttl_s?: unknown;
    };

    if (typeof body.audience !== "string") {
      return res.status(400).json({ error: "audience is required" });
    }
    if (typeof body.tenant_id !== "string" || body.tenant_id.length === 0) {
      return res.status(400).json({ error: "tenant_id is required" });
    }

    // Authorisation: caller must be admin/owner of the tenant they are
    // acting on behalf of. Lower roles (member/viewer) cannot mint tokens.
    const role = await getMembership(
      { url: supabaseUrl, serviceRoleKey },
      userId,
      body.tenant_id,
      fetchImpl,
    );
    if (!role) {
      return res
        .status(403)
        .json({ error: "Not a member of the requested tenant" });
    }
    if (!ELEVATED_ROLES.has(role)) {
      return res
        .status(403)
        .json({ error: "Insufficient role: owner or admin required" });
    }

    try {
      const result = await issueServiceToken(
        {
          audience: body.audience as ServiceAudience,
          scope: body.scope as string[],
          subject: `user:${userId}`,
          tenantId: body.tenant_id,
          ttlSeconds: body.ttl_s as number | undefined,
        },
        { signingSecret, issuer },
      );
      return res.status(200).json({
        access_token: result.access_token,
        expires_in: result.expires_in,
        token_type: "service",
      });
    } catch (e) {
      if (e instanceof ServiceTokenError) {
        return res.status(400).json({ error: e.code, message: e.message });
      }
      throw e;
    }
  };
}

const defaultHandler = createIssueServiceTokenHandler();
export default defaultHandler;
