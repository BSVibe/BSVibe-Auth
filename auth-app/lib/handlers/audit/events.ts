import type { VercelRequest, VercelResponse } from "../_lib/types";
import { verifyServiceTokenSignature, decodeJwtPayload } from "../_lib/service-token";

export interface AuditEventsHandlerDeps {
  fetchImpl?: typeof fetch;
  /** Override now() for deterministic tests. */
  now?: () => number;
}

interface ServiceTokenClaims {
  iss?: string;
  sub?: string;
  aud?: string;
  scope?: string;
  iat?: number;
  exp?: number;
  token_type?: string;
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

interface RejectedEvent {
  event_id: string;
  reason: string;
}

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EVENT_TYPE_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
const ACTOR_TYPES = new Set(["user", "service", "system"]);
const REQUIRED_AUDIENCE = "bsvibe-auth";
const REQUIRED_SCOPE = "audit.write";
const MAX_BATCH = 100;

function isValidActor(value: unknown): value is { type: string; id: string } {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.type !== "string" || !ACTOR_TYPES.has(v.type)) return false;
  if (typeof v.id !== "string" || v.id.length === 0) return false;
  return true;
}

function validateEvent(event: IncomingEvent): { ok: true } | { ok: false; reason: string } {
  if (typeof event.event_id !== "string" || !UUID_PATTERN.test(event.event_id)) {
    return { ok: false, reason: "event_id must be a UUID" };
  }
  if (typeof event.event_type !== "string" || !EVENT_TYPE_PATTERN.test(event.event_type)) {
    return { ok: false, reason: "event_type must be dotted lowercase namespace" };
  }
  if (typeof event.occurred_at !== "string" || Number.isNaN(Date.parse(event.occurred_at))) {
    return { ok: false, reason: "occurred_at must be an ISO 8601 timestamp" };
  }
  if (!isValidActor(event.actor)) {
    return { ok: false, reason: "actor must be {type, id}" };
  }
  if (typeof event.tenant_id !== "string" || event.tenant_id.length === 0) {
    return { ok: false, reason: "tenant_id is required" };
  }
  if (event.data !== undefined && (typeof event.data !== "object" || event.data === null || Array.isArray(event.data))) {
    return { ok: false, reason: "data must be an object" };
  }
  if (event.trace_id !== undefined && typeof event.trace_id !== "string") {
    return { ok: false, reason: "trace_id must be a string" };
  }
  return { ok: true };
}

export function createAuditEventsHandler(deps: AuditEventsHandlerDeps = {}) {
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

    // ---- Auth: service JWT ----
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

    // ---- Body validation ----
    const body = (req.body ?? {}) as { events?: unknown };
    if (!Array.isArray(body.events)) {
      return res.status(400).json({ error: "events must be an array" });
    }
    if (body.events.length === 0) {
      return res.status(400).json({ error: "events must be non-empty" });
    }
    if (body.events.length > MAX_BATCH) {
      return res
        .status(400)
        .json({ error: `events batch exceeds max of ${MAX_BATCH}` });
    }

    const accepted: Array<{
      id: string;
      event_type: string;
      event_data: Record<string, unknown>;
      occurred_at: string;
      tenant_id: string;
      actor: Record<string, unknown>;
      trace_id?: string;
    }> = [];
    const rejected: RejectedEvent[] = [];

    for (const raw of body.events) {
      if (!raw || typeof raw !== "object") {
        rejected.push({ event_id: "<invalid>", reason: "event must be an object" });
        continue;
      }
      const event = raw as IncomingEvent;
      const idAsString =
        typeof event.event_id === "string" ? event.event_id : "<invalid>";
      const check = validateEvent(event);
      if (!check.ok) {
        rejected.push({ event_id: idAsString, reason: check.reason });
        continue;
      }
      accepted.push({
        id: event.event_id as string,
        event_type: event.event_type as string,
        event_data: ((event.data as Record<string, unknown>) ?? {}),
        occurred_at: event.occurred_at as string,
        tenant_id: event.tenant_id as string,
        actor: event.actor as Record<string, unknown>,
        ...(typeof event.trace_id === "string" ? { trace_id: event.trace_id } : {}),
      });
    }

    if (accepted.length === 0) {
      return res.status(200).json({ accepted: 0, rejected });
    }

    // ---- Upstream INSERT (PostgREST, ON CONFLICT DO NOTHING via Prefer) ----
    const url = `${supabaseUrl}/rest/v1/audit_events`;
    let resp: Response;
    try {
      resp = await fetchImpl(url, {
        method: "POST",
        headers: {
          apikey: serviceRoleKey,
          Authorization: `Bearer ${serviceRoleKey}`,
          "Content-Type": "application/json",
          Prefer: "return=minimal,resolution=ignore-duplicates",
        },
        body: JSON.stringify(accepted),
      });
    } catch (e) {
      return res.status(502).json({
        error: "Upstream audit store unavailable",
        detail: e instanceof Error ? e.message : String(e),
      });
    }
    if (!resp.ok) {
      return res.status(502).json({
        error: "Upstream audit store rejected batch",
        upstream_status: resp.status,
      });
    }

    return res.status(200).json({ accepted: accepted.length, rejected });
  };
}

const defaultHandler = createAuditEventsHandler();
export default defaultHandler;
