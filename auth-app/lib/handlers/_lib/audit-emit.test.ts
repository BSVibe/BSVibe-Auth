import { describe, it, expect, vi } from "vitest";
import { emitAuditEvent, isValidEventType } from "./audit-emit";

const cfg = {
  url: "https://test.supabase.co",
  serviceRoleKey: "service-role-key",
};

function makeFetchOk() {
  return vi.fn(async () =>
    new Response(null, { status: 201 }),
  ) as unknown as typeof fetch;
}

function makeFetchErr(status = 500) {
  return vi.fn(async () =>
    new Response(JSON.stringify({ message: "boom" }), {
      status,
      headers: { "content-type": "application/json" },
    }),
  ) as unknown as typeof fetch;
}

describe("isValidEventType", () => {
  it("accepts dotted lowercase event types", () => {
    expect(isValidEventType("auth.session.started")).toBe(true);
    expect(isValidEventType("authz.service_token.issued")).toBe(true);
    expect(isValidEventType("auth.user.created")).toBe(true);
  });
  it("rejects malformed types", () => {
    expect(isValidEventType("")).toBe(false);
    expect(isValidEventType("noseparator")).toBe(false);
    expect(isValidEventType("Bad.Case.Type")).toBe(false);
    expect(isValidEventType("trailing.")).toBe(false);
  });
});

describe("emitAuditEvent", () => {
  it("POSTs an event row to the audit_events REST endpoint with service role headers", async () => {
    const fetchImpl = makeFetchOk();
    const result = await emitAuditEvent(
      cfg,
      {
        eventType: "auth.session.started",
        tenantId: "00000000-0000-0000-0000-0000000000aa",
        actor: { type: "user", id: "user-1", email: "u@example.com" },
        data: { method: "password" },
      },
      { fetchImpl, now: () => 1_700_000_000_000 },
    );

    expect(result.ok).toBe(true);
    const calls = (fetchImpl as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    expect(calls).toHaveLength(1);
    const [url, init] = calls[0] as [string, RequestInit];
    expect(url).toBe("https://test.supabase.co/rest/v1/audit_events");
    expect(init.method).toBe("POST");
    const headers = init.headers as Record<string, string>;
    expect(headers.apikey).toBe("service-role-key");
    expect(headers.Authorization).toBe("Bearer service-role-key");
    expect(headers["Content-Type"]).toContain("application/json");
    // Postgrest "merge-duplicates" so re-emit is idempotent on event_id.
    expect(headers.Prefer).toContain("resolution=ignore-duplicates");

    const body = JSON.parse(init.body as string);
    expect(body.event_type).toBe("auth.session.started");
    expect(body.tenant_id).toBe("00000000-0000-0000-0000-0000000000aa");
    expect(body.actor).toEqual({
      type: "user",
      id: "user-1",
      email: "u@example.com",
    });
    expect(body.event_data).toEqual({ method: "password" });
    expect(typeof body.id).toBe("string");
    expect(body.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(body.occurred_at).toBe(new Date(1_700_000_000_000).toISOString());
  });

  it("returns ok:false but does not throw when the upstream rejects", async () => {
    const fetchImpl = makeFetchErr(500);
    const result = await emitAuditEvent(
      cfg,
      {
        eventType: "auth.user.created",
        tenantId: "00000000-0000-0000-0000-0000000000aa",
        actor: { type: "user", id: "user-1" },
        data: {},
      },
      { fetchImpl },
    );
    expect(result.ok).toBe(false);
    expect(result.status).toBe(500);
  });

  it("rejects malformed event_type before calling fetch", async () => {
    const fetchImpl = vi.fn() as unknown as typeof fetch;
    await expect(
      emitAuditEvent(
        cfg,
        {
          // @ts-expect-error testing runtime validation
          eventType: "BadEvent",
          tenantId: "00000000-0000-0000-0000-0000000000aa",
          actor: { type: "user", id: "user-1" },
          data: {},
        },
        { fetchImpl },
      ),
    ).rejects.toThrow(/event_type/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("uses caller-supplied event_id when provided (idempotency)", async () => {
    const fetchImpl = makeFetchOk();
    const eventId = "11111111-1111-1111-1111-111111111111";
    await emitAuditEvent(
      cfg,
      {
        eventId,
        eventType: "auth.tenant.switched",
        tenantId: "00000000-0000-0000-0000-0000000000aa",
        actor: { type: "user", id: "user-1" },
        data: { to_tenant_id: "00000000-0000-0000-0000-0000000000bb" },
      },
      { fetchImpl },
    );
    const calls = (fetchImpl as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    const body = JSON.parse((calls[0][1] as RequestInit).body as string);
    expect(body.id).toBe(eventId);
  });

  it("includes trace_id when provided", async () => {
    const fetchImpl = makeFetchOk();
    await emitAuditEvent(
      cfg,
      {
        eventType: "authz.service_token.issued",
        tenantId: "00000000-0000-0000-0000-0000000000aa",
        actor: { type: "user", id: "user-1" },
        data: {},
        traceId: "trace-abc",
      },
      { fetchImpl },
    );
    const calls = (fetchImpl as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    const body = JSON.parse((calls[0][1] as RequestInit).body as string);
    expect(body.trace_id).toBe("trace-abc");
  });

  it("never throws on network errors — emit must not break business flow", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const result = await emitAuditEvent(
      cfg,
      {
        eventType: "auth.session.started",
        tenantId: "00000000-0000-0000-0000-0000000000aa",
        actor: { type: "user", id: "user-1" },
        data: {},
      },
      { fetchImpl },
    );
    expect(result.ok).toBe(false);
    expect(result.error).toBeDefined();
  });
});
