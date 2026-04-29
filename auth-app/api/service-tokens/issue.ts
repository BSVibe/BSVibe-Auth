import type { VercelRequest, VercelResponse } from "../_lib/types";
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
import {
  emitAuditEventBestEffort,
  type AuditEmitInput,
  type AuditEmitResult,
} from "../_lib/audit-emit";

export type EmitAuditFn = (
  cfg: { url: string; serviceRoleKey: string },
  input: AuditEmitInput,
) => Promise<AuditEmitResult>;

export interface IssueServiceTokenHandlerDeps {
  getMembership?: (
    cfg: SupabaseConfig,
    userId: string,
    tenantId: string,
    fetchImpl?: typeof fetch,
  ) => Promise<TenantRole | null>;
  verifyAccessToken?: (
    cfg: { url: string; anonKey: string },
    accessToken: string,
    fetchImpl?: typeof fetch,
  ) => Promise<string | null>;
  fetchImpl?: typeof fetch;
  emitAudit?: EmitAuditFn;
}

interface SupabaseUserResponse {
  id?: string;
}

export async function verifySupabaseAccessToken(
  cfg: { url: string; anonKey: string },
  accessToken: string,
  fetchImpl: typeof fetch = fetch,
): Promise<string | null> {
  const resp = await fetchImpl(`${cfg.url}/auth/v1/user`, {
    method: "GET",
    headers: {
      apikey: cfg.anonKey,
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
  });
  if (!resp.ok) return null;
  const user = (await resp.json()) as SupabaseUserResponse;
  return typeof user.id === "string" && user.id.length > 0 ? user.id : null;
}

const ELEVATED_ROLES: ReadonlySet<TenantRole> = new Set(["owner", "admin"]);

export function createIssueServiceTokenHandler(
  deps: IssueServiceTokenHandlerDeps = {},
) {
  const getMembership = deps.getMembership ?? getMembershipImpl;
  const verifyAccessToken = deps.verifyAccessToken ?? verifySupabaseAccessToken;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const emitAudit: EmitAuditFn =
    deps.emitAudit ??
    ((cfg, input) =>
      emitAuditEventBestEffort(cfg, input, { fetchImpl }));

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
    const supabaseAnonKey =
      process.env.SUPABASE_ANON_KEY ?? process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    const signingSecret = process.env.SERVICE_TOKEN_SIGNING_SECRET;
    const issuer =
      process.env.SERVICE_TOKEN_ISSUER || "https://auth.bsvibe.dev";

    if (!supabaseUrl || !supabaseAnonKey || !serviceRoleKey) {
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

    const userId = await verifyAccessToken(
      { url: supabaseUrl, anonKey: supabaseAnonKey },
      accessToken,
      fetchImpl,
    );
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
      // Emit authz.service_token.issued (best-effort, fire-and-forget).
      await emitAudit(
        { url: supabaseUrl, serviceRoleKey },
        {
          eventType: "authz.service_token.issued",
          tenantId: body.tenant_id,
          actor: { type: "user", id: userId },
          data: {
            audience: result.payload.aud,
            scope: result.payload.scope.split(" ").filter(Boolean),
            ttl_s: result.expires_in,
          },
        },
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
