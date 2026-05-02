import type { VercelRequest, VercelResponse } from "../_lib/types";
import type { SupabaseConfig } from "../_lib/tenants";
import {
  defaultHasAlertPermission,
  type HasAlertPermissionFn,
} from "../_lib/alert-perms";
import {
  deleteAlertRoute,
  insertAlertRoute,
  listAlertRoutes,
  updateAlertRoute,
  type AlertChannel,
  type AlertRouteInput,
  type AlertRoutePatch,
  type AlertSeverity,
} from "../_lib/alert-routes";

/**
 * /api/alerts/rules — list/create alert routing rules.
 * /api/alerts/rules/[id] — patch/delete one rule.
 *
 * Authentication: end-user JWT (auth.users access_token). The handler
 * decodes ``sub`` and looks up tenant membership; D18's
 * ``core.alerts.read`` / ``core.alerts.manage`` permissions are
 * resolved through :func:`defaultHasAlertPermission`. The dependency
 * surface mirrors :mod:`api/audit/query` so the same swap to bsvibe-authz
 * applies once P0.4 lands.
 */

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VALID_SEVERITIES: ReadonlySet<AlertSeverity> = new Set([
  "info",
  "warning",
  "critical",
]);
const VALID_CHANNELS: ReadonlySet<AlertChannel> = new Set([
  "telegram",
  "slack",
  "structlog",
]);
// Mirrors bsvibe-audit AuditAlertRule pattern grammar — exact name or trailing
// ``*``. Internal asterisks are not supported.
const EVENT_PATTERN = /^(?:\*|[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*(?:\.\*)?)$/;

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

function setCors(res: VercelResponse): void {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

interface IncomingRule {
  name?: unknown;
  event_pattern?: unknown;
  severity?: unknown;
  channel?: unknown;
  config?: unknown;
  enabled?: unknown;
  tenant_id?: unknown;
}

function validateRuleInput(
  raw: unknown,
  { partial }: { partial: boolean },
): { ok: true; value: AlertRouteInput | AlertRoutePatch } | { ok: false; reason: string } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, reason: "request body must be an object" };
  }
  const r = raw as IncomingRule;
  const out: AlertRoutePatch = {};

  if (r.name !== undefined) {
    if (typeof r.name !== "string" || r.name.length === 0 || r.name.length > 200) {
      return { ok: false, reason: "name must be a non-empty string ≤200 chars" };
    }
    out.name = r.name;
  } else if (!partial) {
    return { ok: false, reason: "name is required" };
  }

  if (r.event_pattern !== undefined) {
    if (typeof r.event_pattern !== "string" || !EVENT_PATTERN.test(r.event_pattern)) {
      return { ok: false, reason: "event_pattern must match dotted-glob grammar" };
    }
    out.event_pattern = r.event_pattern;
  } else if (!partial) {
    return { ok: false, reason: "event_pattern is required" };
  }

  if (r.severity !== undefined) {
    if (typeof r.severity !== "string" || !VALID_SEVERITIES.has(r.severity as AlertSeverity)) {
      return { ok: false, reason: `severity must be one of ${[...VALID_SEVERITIES].join(", ")}` };
    }
    out.severity = r.severity as AlertSeverity;
  } else if (!partial) {
    return { ok: false, reason: "severity is required" };
  }

  if (r.channel !== undefined) {
    if (typeof r.channel !== "string" || !VALID_CHANNELS.has(r.channel as AlertChannel)) {
      return { ok: false, reason: `channel must be one of ${[...VALID_CHANNELS].join(", ")}` };
    }
    out.channel = r.channel as AlertChannel;
  } else if (!partial) {
    return { ok: false, reason: "channel is required" };
  }

  if (r.config !== undefined) {
    if (typeof r.config !== "object" || r.config === null || Array.isArray(r.config)) {
      return { ok: false, reason: "config must be an object" };
    }
    out.config = r.config as Record<string, unknown>;
  }

  if (r.enabled !== undefined) {
    if (typeof r.enabled !== "boolean") {
      return { ok: false, reason: "enabled must be a boolean" };
    }
    out.enabled = r.enabled;
  }

  return { ok: true, value: out };
}

function getRouteIdFromRequest(req: VercelRequest): string | null {
  if (typeof req.query?.id === "string" && req.query.id.length > 0) {
    return req.query.id;
  }
  // Fallback: parse from URL path ``/api/alerts/rules/<id>``.
  const url = req.url ?? "";
  const m = /\/alerts\/rules\/([^/?#]+)/.exec(url);
  return m ? m[1] : null;
}

export interface AlertRulesHandlerDeps {
  hasAlertPermission?: HasAlertPermissionFn;
  fetchImpl?: typeof fetch;
}

export function createAlertRulesHandler(deps: AlertRulesHandlerDeps = {}) {
  const hasAlertPermission =
    deps.hasAlertPermission ?? defaultHasAlertPermission;
  const fetchImpl = deps.fetchImpl ?? fetch;

  return async function handler(req: VercelRequest, res: VercelResponse) {
    if (req.method === "OPTIONS") {
      setCors(res);
      return res.status(204).end();
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

    const cfg: SupabaseConfig = { url: supabaseUrl, serviceRoleKey };

    if (req.method === "GET") {
      const tenantId = (req.query?.tenant_id as string | undefined) ?? "";
      if (!tenantId) {
        return res.status(400).json({ error: "tenant_id is required" });
      }
      const allowed = await hasAlertPermission(
        cfg,
        userId,
        tenantId,
        "core.alerts.read",
        fetchImpl,
      );
      if (!allowed) {
        return res
          .status(403)
          .json({ error: "core.alerts.read required on tenant" });
      }
      try {
        const rows = await listAlertRoutes(cfg, tenantId, fetchImpl);
        return res.status(200).json({ rules: rows });
      } catch (e) {
        return res.status(502).json({
          error: "Upstream alert_routes unavailable",
          detail: e instanceof Error ? e.message : String(e),
        });
      }
    }

    if (req.method === "POST") {
      const body = (req.body ?? {}) as IncomingRule;
      const tenantId = body.tenant_id;
      if (typeof tenantId !== "string" || tenantId.length === 0) {
        return res.status(400).json({ error: "tenant_id is required" });
      }
      const allowed = await hasAlertPermission(
        cfg,
        userId,
        tenantId,
        "core.alerts.manage",
        fetchImpl,
      );
      if (!allowed) {
        return res
          .status(403)
          .json({ error: "core.alerts.manage required on tenant" });
      }
      const check = validateRuleInput(body, { partial: false });
      if (!check.ok) {
        return res.status(400).json({ error: check.reason });
      }
      try {
        const row = await insertAlertRoute(
          cfg,
          tenantId,
          check.value as AlertRouteInput,
          fetchImpl,
        );
        return res.status(201).json({ rule: row });
      } catch (e) {
        return res.status(502).json({
          error: "Upstream alert_routes unavailable",
          detail: e instanceof Error ? e.message : String(e),
        });
      }
    }

    if (req.method === "PATCH" || req.method === "DELETE") {
      const routeId = getRouteIdFromRequest(req);
      if (!routeId || !UUID_PATTERN.test(routeId)) {
        return res.status(400).json({ error: "rule id is required" });
      }
      const body = (req.body ?? {}) as IncomingRule;
      const tenantId =
        (typeof body.tenant_id === "string" ? body.tenant_id : null) ??
        ((req.query?.tenant_id as string | undefined) ?? null);
      if (!tenantId) {
        return res.status(400).json({ error: "tenant_id is required" });
      }
      const allowed = await hasAlertPermission(
        cfg,
        userId,
        tenantId,
        "core.alerts.manage",
        fetchImpl,
      );
      if (!allowed) {
        return res
          .status(403)
          .json({ error: "core.alerts.manage required on tenant" });
      }

      if (req.method === "PATCH") {
        const check = validateRuleInput(body, { partial: true });
        if (!check.ok) {
          return res.status(400).json({ error: check.reason });
        }
        const patch = check.value as AlertRoutePatch;
        if (Object.keys(patch).length === 0) {
          return res.status(400).json({ error: "at least one field must be patched" });
        }
        try {
          const row = await updateAlertRoute(
            cfg,
            tenantId,
            routeId,
            patch,
            fetchImpl,
          );
          if (!row) return res.status(404).json({ error: "rule not found" });
          return res.status(200).json({ rule: row });
        } catch (e) {
          return res.status(502).json({
            error: "Upstream alert_routes unavailable",
            detail: e instanceof Error ? e.message : String(e),
          });
        }
      }

      // DELETE
      try {
        const ok = await deleteAlertRoute(cfg, tenantId, routeId, fetchImpl);
        if (!ok) return res.status(404).json({ error: "rule not found" });
        return res.status(204).end();
      } catch (e) {
        return res.status(502).json({
          error: "Upstream alert_routes unavailable",
          detail: e instanceof Error ? e.message : String(e),
        });
      }
    }

    return res.status(405).json({ error: "Method not allowed" });
  };
}

const defaultHandler = createAlertRulesHandler();
export default defaultHandler;
