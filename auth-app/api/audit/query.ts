import type { VercelRequest, VercelResponse } from "../_lib/types";
import type { SupabaseConfig } from "../_lib/tenants";
import { getMembership } from "../_lib/tenants";

/**
 * core.audit.read permission check.
 *
 * Phase 0 P0.4 will introduce bsvibe-authz `require_permission` (Python).
 * Until that lands, this handler enforces the same contract via the
 * `tenant_members` table — owners and admins of a tenant are granted
 * `core.audit.read` for that tenant. The signature accepts the permission
 * name so the implementation can be swapped to bsvibe-authz without
 * touching call sites.
 */
export async function defaultHasAuditReadPermission(
  cfg: SupabaseConfig,
  userId: string,
  tenantId: string,
  permission: string,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  if (permission !== "core.audit.read") return false;
  const role = await getMembership(cfg, userId, tenantId, fetchImpl);
  if (!role) return false;
  return role === "owner" || role === "admin";
}

export type HasAuditReadPermissionFn = (
  cfg: SupabaseConfig,
  userId: string,
  tenantId: string,
  permission: string,
  fetchImpl?: typeof fetch,
) => Promise<boolean>;

export interface AuditQueryHandlerDeps {
  hasAuditReadPermission?: HasAuditReadPermissionFn;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

interface AccessTokenPayload {
  sub?: string;
  exp?: number;
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

const MAX_RANGE_MS = 90 * 24 * 60 * 60 * 1000;
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;
const EVENT_TYPE_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface QueryBody {
  tenant_id?: unknown;
  event_types?: unknown;
  actor?: unknown;
  time_range?: unknown;
  limit?: unknown;
  cursor?: unknown;
}

export function createAuditQueryHandler(deps: AuditQueryHandlerDeps = {}) {
  const hasAuditReadPermission =
    deps.hasAuditReadPermission ?? defaultHasAuditReadPermission;
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

    const body = (req.body ?? {}) as QueryBody;
    const tenantId = body.tenant_id;
    if (typeof tenantId !== "string" || tenantId.length === 0) {
      return res.status(400).json({ error: "tenant_id is required" });
    }

    // Validate event_types
    let eventTypes: string[] | null = null;
    if (body.event_types !== undefined) {
      if (!Array.isArray(body.event_types)) {
        return res.status(400).json({ error: "event_types must be an array" });
      }
      const invalid = body.event_types.find(
        (t) => typeof t !== "string" || !EVENT_TYPE_PATTERN.test(t),
      );
      if (invalid !== undefined) {
        return res
          .status(400)
          .json({ error: `Invalid event_type: ${String(invalid)}` });
      }
      eventTypes = body.event_types as string[];
    }

    // Validate actor (only id supported in v0.1)
    let actorIdFilter: string | null = null;
    if (body.actor !== undefined) {
      if (
        typeof body.actor !== "object" ||
        body.actor === null ||
        Array.isArray(body.actor)
      ) {
        return res.status(400).json({ error: "actor must be an object" });
      }
      const aid = (body.actor as Record<string, unknown>).id;
      if (aid !== undefined) {
        if (typeof aid !== "string" || aid.length === 0) {
          return res.status(400).json({ error: "actor.id must be a string" });
        }
        actorIdFilter = aid;
      }
    }

    // Validate time_range; cap at 90 days
    let since: string | null = null;
    let until: string | null = null;
    if (body.time_range !== undefined) {
      if (
        typeof body.time_range !== "object" ||
        body.time_range === null ||
        Array.isArray(body.time_range)
      ) {
        return res.status(400).json({ error: "time_range must be an object" });
      }
      const tr = body.time_range as Record<string, unknown>;
      if (tr.since !== undefined) {
        if (typeof tr.since !== "string" || Number.isNaN(Date.parse(tr.since))) {
          return res
            .status(400)
            .json({ error: "time_range.since must be ISO 8601" });
        }
        since = tr.since;
      }
      if (tr.until !== undefined) {
        if (typeof tr.until !== "string" || Number.isNaN(Date.parse(tr.until))) {
          return res
            .status(400)
            .json({ error: "time_range.until must be ISO 8601" });
        }
        until = tr.until;
      }
      if (since && until) {
        const span = Date.parse(until) - Date.parse(since);
        if (span > MAX_RANGE_MS) {
          return res
            .status(400)
            .json({ error: "time_range exceeds 90 days" });
        }
      }
    }

    let limit = DEFAULT_LIMIT;
    if (body.limit !== undefined) {
      if (
        typeof body.limit !== "number" ||
        !Number.isInteger(body.limit) ||
        body.limit < 1
      ) {
        return res
          .status(400)
          .json({ error: "limit must be a positive integer" });
      }
      limit = Math.min(body.limit, MAX_LIMIT);
    }

    let cursor: string | null = null;
    if (body.cursor !== undefined) {
      if (typeof body.cursor !== "string") {
        return res.status(400).json({ error: "cursor must be a string" });
      }
      // Cursor encodes the occurred_at of the last seen row (ISO 8601).
      if (Number.isNaN(Date.parse(body.cursor))) {
        return res.status(400).json({ error: "cursor must be ISO 8601" });
      }
      cursor = body.cursor;
    }

    // ---- Permission check ----
    const cfg: SupabaseConfig = { url: supabaseUrl, serviceRoleKey };
    const allowed = await hasAuditReadPermission(
      cfg,
      userId,
      tenantId,
      "core.audit.read",
      fetchImpl,
    );
    if (!allowed) {
      return res
        .status(403)
        .json({ error: "core.audit.read required on tenant" });
    }

    // ---- Build PostgREST URL ----
    const url = new URL(`${supabaseUrl}/rest/v1/audit_events`);
    url.searchParams.set(
      "select",
      "id,event_type,occurred_at,ingested_at,tenant_id,actor,event_data,trace_id",
    );
    url.searchParams.set("tenant_id", `eq.${tenantId}`);
    url.searchParams.set("order", "occurred_at.desc");
    url.searchParams.set("limit", String(limit));
    if (eventTypes && eventTypes.length > 0) {
      url.searchParams.set("event_type", `in.(${eventTypes.join(",")})`);
    }
    if (actorIdFilter) {
      url.searchParams.set("actor->>id", `eq.${actorIdFilter}`);
    }
    if (since) {
      url.searchParams.append("occurred_at", `gte.${since}`);
    }
    if (until) {
      url.searchParams.append("occurred_at", `lte.${until}`);
    }
    if (cursor) {
      // Page forward: rows older than the last seen occurred_at.
      url.searchParams.append("occurred_at", `lt.${cursor}`);
    }
    // Sanity guard
    void UUID_PATTERN;

    let resp: Response;
    try {
      resp = await fetchImpl(url.toString(), {
        headers: {
          apikey: serviceRoleKey,
          Authorization: `Bearer ${serviceRoleKey}`,
          Accept: "application/json",
        },
      });
    } catch (e) {
      return res.status(502).json({
        error: "Upstream audit store unavailable",
        detail: e instanceof Error ? e.message : String(e),
      });
    }
    if (!resp.ok) {
      return res.status(502).json({
        error: "Upstream audit store rejected query",
        upstream_status: resp.status,
      });
    }
    const rows = (await resp.json()) as Array<{
      occurred_at: string;
    }>;
    const next_cursor = rows.length === limit
      ? rows[rows.length - 1].occurred_at
      : null;

    return res.status(200).json({ events: rows, next_cursor });
  };
}

const defaultHandler = createAuditQueryHandler();
export default defaultHandler;
