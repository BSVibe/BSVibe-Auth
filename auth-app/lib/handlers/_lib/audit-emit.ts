/**
 * Audit event emit helper.
 *
 * Writes a single AuditEventBase-shaped row into the BSVibe-Auth Supabase
 * `audit_events` table via PostgREST, using the service role key so RLS is
 * bypassed (writes are authoritatively allowed for the auth-app server).
 *
 * Per BSVibe_Audit_Design.md §3 the canonical collector path is
 *   POST /api/audit/events  (idempotent, batch).
 * Auth-emitted events are sourced from the same DB so we avoid the loopback
 * relay and INSERT directly. The shape we write matches what the
 * `/api/audit/events` endpoint would write — so collectors and inline
 * emits land in the same table.
 *
 * Failure handling: this helper MUST NOT throw on infrastructure errors —
 * a failing audit log must never break the user-facing flow it observes.
 * Tests assert this contract explicitly.
 */

export interface AuditActor {
  type: "user" | "service" | "system";
  id: string;
  email?: string;
  [key: string]: unknown;
}

export interface AuditEmitInput {
  /** Optional pre-generated event id (UUID). If omitted, one is generated. */
  eventId?: string;
  /** Dotted lowercase event type, e.g. "auth.session.started". */
  eventType: string;
  /** Tenant the event is scoped to. */
  tenantId: string;
  /** Actor that caused the event. */
  actor: AuditActor;
  /** Free-form payload. Must NOT include secrets/PII level L3 fields. */
  data: Record<string, unknown>;
  /** OpenTelemetry trace id (optional). */
  traceId?: string;
  /** Override occurredAt (ISO string). Defaults to now(). */
  occurredAt?: string;
}

export interface SupabaseAuditConfig {
  url: string;
  serviceRoleKey: string;
}

export interface AuditEmitOptions {
  fetchImpl?: typeof fetch;
  /** Override now() for deterministic tests. */
  now?: () => number;
}

export interface AuditEmitResult {
  ok: boolean;
  status?: number;
  error?: string;
  eventId: string;
}

const EVENT_TYPE_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

export function isValidEventType(value: string): boolean {
  if (typeof value !== "string" || value.length === 0) return false;
  return EVENT_TYPE_PATTERN.test(value);
}

function generateUuid(): string {
  // crypto.randomUUID is available in Node 18+ and the Web Crypto API.
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  // Fallback (should not happen on Vercel/Next.js runtime).
  const bytes = new Uint8Array(16);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  // RFC 4122 v4 markers.
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export async function emitAuditEvent(
  cfg: SupabaseAuditConfig,
  input: AuditEmitInput,
  opts: AuditEmitOptions = {},
): Promise<AuditEmitResult> {
  if (!isValidEventType(input.eventType)) {
    throw new Error(`invalid_event_type: ${input.eventType}`);
  }
  const fetchImpl = opts.fetchImpl ?? fetch;
  const now = opts.now ?? Date.now;
  const eventId = input.eventId ?? generateUuid();
  const occurredAt = input.occurredAt ?? new Date(now()).toISOString();

  const row = {
    id: eventId,
    event_type: input.eventType,
    event_data: input.data ?? {},
    occurred_at: occurredAt,
    tenant_id: input.tenantId,
    actor: input.actor,
    ...(input.traceId ? { trace_id: input.traceId } : {}),
  };

  const url = `${cfg.url}/rest/v1/audit_events`;
  try {
    const resp = await fetchImpl(url, {
      method: "POST",
      headers: {
        apikey: cfg.serviceRoleKey,
        Authorization: `Bearer ${cfg.serviceRoleKey}`,
        "Content-Type": "application/json",
        // ON CONFLICT DO NOTHING — re-emit of the same event_id is a no-op.
        Prefer: "return=minimal,resolution=ignore-duplicates",
      },
      body: JSON.stringify(row),
    });
    if (!resp.ok) {
      return { ok: false, status: resp.status, eventId };
    }
    return { ok: true, status: resp.status, eventId };
  } catch (e) {
    return {
      ok: false,
      eventId,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

/**
 * Best-effort fire-and-forget wrapper around `emitAuditEvent`.
 *
 * Used by handlers that already returned to the user — the emit must not
 * delay the response or surface errors. Errors are swallowed (caller may
 * read structured logs to diagnose).
 */
export function emitAuditEventBestEffort(
  cfg: SupabaseAuditConfig,
  input: AuditEmitInput,
  opts: AuditEmitOptions = {},
): Promise<AuditEmitResult> {
  return emitAuditEvent(cfg, input, opts).catch((e) => ({
    ok: false,
    eventId: input.eventId ?? "",
    error: e instanceof Error ? e.message : String(e),
  }));
}
