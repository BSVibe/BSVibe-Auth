import type { VercelRequest, VercelResponse } from "../_lib/types";
import {
  decodeJwtPayload,
  verifyServiceTokenSignature,
} from "../_lib/service-token";
import {
  listEnabledAlertRoutes,
  type AlertRoute,
  type AlertSeverity,
} from "../_lib/alert-routes";

/**
 * POST /api/alerts/dispatch — central alert routing for D18.
 *
 * Auth: service JWT signed by SERVICE_TOKEN_SIGNING_SECRET, audience
 * ``bsvibe-auth``, scope must include ``alerts.dispatch``. Mirrors
 * /api/audit/events. End-user JWTs cannot dispatch directly.
 *
 * Request body: AuditEventBase-shaped envelope
 *   { event_id, event_type, occurred_at, actor, tenant_id, trace_id?, data? }
 *
 * The handler:
 *   1. validates the event,
 *   2. loads every enabled alert_route for the tenant,
 *   3. evaluates ``event_pattern`` (glob with trailing ``*``) and
 *      ``severity`` (min ladder against the data.severity field, default
 *      ``info``),
 *   4. returns the matched rules and a stub delivery result.
 *
 * In Phase 0 the dispatch handler does NOT itself call telegram/slack —
 * actual fan-out remains the bsvibe-alerts client's job. The endpoint is
 * the runtime-tunable rule store + matcher; the channel sinks live in the
 * caller. This matches D-Z2's "3중 안전망" design (stdout fallback in the
 * client even when the dispatch matches zero rules).
 */

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EVENT_TYPE_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
const ACTOR_TYPES = new Set(["user", "service", "system"]);
const REQUIRED_AUDIENCE = "bsvibe-auth";
const REQUIRED_SCOPE = "alerts.dispatch";

const SEVERITY_RANK: Record<AlertSeverity, number> = {
  info: 0,
  warning: 1,
  critical: 2,
};

interface ServiceTokenClaims {
  iss?: string;
  sub?: string;
  aud?: string;
  scope?: string;
  iat?: number;
  exp?: number;
  token_type?: string;
}

export interface DispatchHandlerDeps {
  /** Override for tests — defaults to listEnabledAlertRoutes(). */
  loadRoutes?: (
    cfg: { url: string; serviceRoleKey: string },
    tenantId: string,
    fetchImpl?: typeof fetch,
  ) => Promise<AlertRoute[]>;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

interface IncomingEvent {
  event_id?: unknown;
  event_type?: unknown;
  occurred_at?: unknown;
  actor?: unknown;
  tenant_id?: unknown;
  trace_id?: unknown;
  data?: unknown;
}

interface ValidatedEvent {
  event_id: string;
  event_type: string;
  occurred_at: string;
  actor: { type: string; id: string; [k: string]: unknown };
  tenant_id: string;
  trace_id?: string;
  data: Record<string, unknown>;
}

function validateEvent(
  raw: IncomingEvent,
): { ok: true; value: ValidatedEvent } | { ok: false; reason: string } {
  if (typeof raw.event_id !== "string" || !UUID_PATTERN.test(raw.event_id)) {
    return { ok: false, reason: "event_id must be a UUID" };
  }
  if (
    typeof raw.event_type !== "string" ||
    !EVENT_TYPE_PATTERN.test(raw.event_type)
  ) {
    return { ok: false, reason: "event_type must be dotted lowercase namespace" };
  }
  if (
    typeof raw.occurred_at !== "string" ||
    Number.isNaN(Date.parse(raw.occurred_at))
  ) {
    return { ok: false, reason: "occurred_at must be ISO 8601" };
  }
  if (
    !raw.actor ||
    typeof raw.actor !== "object" ||
    Array.isArray(raw.actor)
  ) {
    return { ok: false, reason: "actor must be an object" };
  }
  const actor = raw.actor as Record<string, unknown>;
  if (typeof actor.type !== "string" || !ACTOR_TYPES.has(actor.type)) {
    return { ok: false, reason: "actor.type must be user|service|system" };
  }
  if (typeof actor.id !== "string" || actor.id.length === 0) {
    return { ok: false, reason: "actor.id must be a non-empty string" };
  }
  if (typeof raw.tenant_id !== "string" || raw.tenant_id.length === 0) {
    return { ok: false, reason: "tenant_id is required" };
  }
  if (
    raw.data !== undefined &&
    (typeof raw.data !== "object" || raw.data === null || Array.isArray(raw.data))
  ) {
    return { ok: false, reason: "data must be an object" };
  }
  if (raw.trace_id !== undefined && typeof raw.trace_id !== "string") {
    return { ok: false, reason: "trace_id must be a string" };
  }

  return {
    ok: true,
    value: {
      event_id: raw.event_id,
      event_type: raw.event_type,
      occurred_at: raw.occurred_at,
      actor: actor as ValidatedEvent["actor"],
      tenant_id: raw.tenant_id,
      data: (raw.data as Record<string, unknown>) ?? {},
      ...(typeof raw.trace_id === "string" ? { trace_id: raw.trace_id } : {}),
    },
  };
}

function patternMatches(pattern: string, value: string): boolean {
  if (pattern === "*" || pattern === value) return true;
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -2);
    return value === prefix || value.startsWith(prefix + ".");
  }
  return false;
}

function inferSeverity(event: ValidatedEvent): AlertSeverity {
  // Producers can hint via ``data.severity``. Anything else → info.
  const raw = (event.data as Record<string, unknown>).severity;
  if (typeof raw === "string" && raw.toLowerCase() in SEVERITY_RANK) {
    return raw.toLowerCase() as AlertSeverity;
  }
  return "info";
}

function evaluateRoute(
  route: AlertRoute,
  event: ValidatedEvent,
  eventSeverity: AlertSeverity,
): boolean {
  if (!route.enabled) return false;
  if (!patternMatches(route.event_pattern, event.event_type)) return false;
  // route.severity is the *minimum* — fire when event ≥ rule.
  return SEVERITY_RANK[eventSeverity] >= SEVERITY_RANK[route.severity];
}

export function createDispatchHandler(deps: DispatchHandlerDeps = {}) {
  const loadRoutes = deps.loadRoutes ?? listEnabledAlertRoutes;
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
    const signingSecret = process.env.SERVICE_TOKEN_SIGNING_SECRET;
    if (!supabaseUrl || !serviceRoleKey) {
      return res.status(500).json({ error: "Auth service not configured" });
    }
    if (!signingSecret) {
      return res
        .status(500)
        .json({ error: "Service token signing secret not configured" });
    }

    // ---- service JWT auth ----
    const authHeader = req.headers.authorization ?? "";
    const token = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!token) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    const sigOk = await verifyServiceTokenSignature(token, signingSecret);
    if (!sigOk) {
      return res.status(401).json({ error: "Invalid service token" });
    }
    let claims: ServiceTokenClaims;
    try {
      claims = decodeJwtPayload<ServiceTokenClaims>(token);
    } catch {
      return res.status(401).json({ error: "Invalid service token" });
    }
    const nowSec = Math.floor((deps.now ? deps.now() : Date.now()) / 1000);
    if (typeof claims.exp !== "number" || claims.exp < nowSec) {
      return res.status(401).json({ error: "Token expired" });
    }
    if (claims.aud !== REQUIRED_AUDIENCE) {
      return res
        .status(403)
        .json({ error: `Invalid audience; expected ${REQUIRED_AUDIENCE}` });
    }
    const scopes = (claims.scope ?? "").split(/\s+/).filter(Boolean);
    if (!scopes.includes(REQUIRED_SCOPE)) {
      return res
        .status(403)
        .json({ error: `Missing required scope ${REQUIRED_SCOPE}` });
    }

    // ---- body validation ----
    const check = validateEvent((req.body ?? {}) as IncomingEvent);
    if (!check.ok) {
      return res.status(400).json({ error: check.reason });
    }
    const event = check.value;
    const eventSeverity = inferSeverity(event);

    // ---- evaluate ----
    let routes: AlertRoute[];
    try {
      routes = await loadRoutes(
        { url: supabaseUrl, serviceRoleKey },
        event.tenant_id,
        fetchImpl,
      );
    } catch (e) {
      return res.status(502).json({
        error: "Upstream alert_routes unavailable",
        detail: e instanceof Error ? e.message : String(e),
      });
    }

    const matched: AlertRoute[] = routes.filter((route) =>
      evaluateRoute(route, event, eventSeverity),
    );

    // Phase 0: the auth-app does not itself fan out to telegram/slack.
    // The bsvibe-alerts client owns delivery + the structlog stdout
    // fallback. Each matched rule is reported as a "delivery descriptor"
    // the client uses to choose its sinks.
    const deliveries = matched.map((route) => ({
      rule_id: route.id,
      name: route.name,
      channel: route.channel,
      severity: route.severity,
      config: route.config,
      enabled: route.enabled,
    }));

    return res.status(200).json({
      event_id: event.event_id,
      event_type: event.event_type,
      tenant_id: event.tenant_id,
      severity: eventSeverity,
      matched_rules: matched.length,
      deliveries,
    });
  };
}

const defaultHandler = createDispatchHandler();
export default defaultHandler;
