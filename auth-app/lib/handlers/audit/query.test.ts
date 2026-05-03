import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createAuditQueryHandler } from "./query";
import { makeReq, makeRes } from "../_lib/test-helpers";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
};

// Minimal user JWT (signature ignored — handler trusts the auth-app session
// which set the cookie and validated upstream). For the v0.1 path we decode
// the sub from the access_token similar to /api/session.
const USER_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiJ1c2VyLWFiYyIsImVtYWlsIjoiYUBiLmMiLCJleHAiOjk5OTk5OTk5OTl9." +
  "sig";

const TENANT_A = "00000000-0000-0000-0000-0000000000aa";
const TENANT_B = "00000000-0000-0000-0000-0000000000bb";

function makeFetchRows(rows: Array<Record<string, unknown>>) {
  return vi.fn(async () =>
    new Response(JSON.stringify(rows), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  ) as unknown as typeof fetch;
}

describe("audit/query handler", () => {
  let envBackup: NodeJS.ProcessEnv;

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });

  afterEach(() => {
    process.env = envBackup;
  });

  it("returns 405 for non-POST", async () => {
    const handler = createAuditQueryHandler({
      hasAuditReadPermission: vi.fn().mockResolvedValue(true),
      fetchImpl: makeFetchRows([]),
    });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("returns 401 when no Authorization header", async () => {
    const handler = createAuditQueryHandler({
      hasAuditReadPermission: vi.fn().mockResolvedValue(true),
      fetchImpl: makeFetchRows([]),
    });
    const req = makeReq({ method: "POST", body: { tenant_id: TENANT_A } });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("returns 400 when tenant_id missing", async () => {
    const handler = createAuditQueryHandler({
      hasAuditReadPermission: vi.fn().mockResolvedValue(true),
      fetchImpl: makeFetchRows([]),
    });
    const req = makeReq({
      method: "POST",
      body: {},
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("returns 403 when caller lacks core.audit.read on tenant", async () => {
    const hasPerm = vi.fn().mockResolvedValue(false);
    const handler = createAuditQueryHandler({
      hasAuditReadPermission: hasPerm,
      fetchImpl: makeFetchRows([]),
    });
    const req = makeReq({
      method: "POST",
      body: { tenant_id: TENANT_A },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
    expect(hasPerm).toHaveBeenCalledWith(
      expect.objectContaining({ url: baseEnv.SUPABASE_URL }),
      "user-abc",
      TENANT_A,
      "core.audit.read",
      expect.anything(),
    );
  });

  it("rejects time_range exceeding 90 days", async () => {
    const handler = createAuditQueryHandler({
      hasAuditReadPermission: vi.fn().mockResolvedValue(true),
      fetchImpl: makeFetchRows([]),
    });
    const req = makeReq({
      method: "POST",
      body: {
        tenant_id: TENANT_A,
        time_range: {
          since: "2026-01-01T00:00:00Z",
          until: "2026-04-30T00:00:00Z",
        },
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect((captured.body as { error: string }).error).toMatch(/90/);
  });

  it("returns rows for valid query", async () => {
    const rows = [
      {
        id: "11111111-1111-1111-1111-111111111111",
        event_type: "auth.session.started",
        occurred_at: "2026-04-27T12:00:00Z",
        ingested_at: "2026-04-27T12:00:01Z",
        tenant_id: TENANT_A,
        actor: { type: "user", id: "user-abc" },
        event_data: {},
        trace_id: null,
      },
    ];
    const fetchImpl = makeFetchRows(rows);
    const handler = createAuditQueryHandler({
      hasAuditReadPermission: vi.fn().mockResolvedValue(true),
      fetchImpl,
    });
    const req = makeReq({
      method: "POST",
      body: {
        tenant_id: TENANT_A,
        event_types: ["auth.session.started", "auth.user.created"],
        time_range: {
          since: "2026-04-20T00:00:00Z",
          until: "2026-04-27T23:00:00Z",
        },
        limit: 50,
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = captured.body as { events: unknown[]; next_cursor: string | null };
    expect(body.events).toHaveLength(1);
    expect(body.next_cursor).toBeNull();

    const calls = (fetchImpl as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    const [url] = calls[0] as [string];
    expect(url).toContain("/rest/v1/audit_events");
    expect(url).toContain(`tenant_id=eq.${TENANT_A}`);
    expect(url).toContain("event_type=in.");
    // PostgREST always orders by occurred_at desc — confirm the query carries it.
    expect(decodeURIComponent(url)).toContain("order=occurred_at.desc");
  });

  it("rejects cross-tenant requests when caller lacks permission on requested tenant", async () => {
    const hasPerm = vi.fn(async (_cfg, _user, tenantId) => tenantId === TENANT_A);
    const handler = createAuditQueryHandler({
      hasAuditReadPermission: hasPerm,
      fetchImpl: makeFetchRows([]),
    });
    const req = makeReq({
      method: "POST",
      body: { tenant_id: TENANT_B },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
  });

  it("filters by actor when provided", async () => {
    const fetchImpl = makeFetchRows([]);
    const handler = createAuditQueryHandler({
      hasAuditReadPermission: vi.fn().mockResolvedValue(true),
      fetchImpl,
    });
    const req = makeReq({
      method: "POST",
      body: {
        tenant_id: TENANT_A,
        actor: { id: "user-abc" },
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const calls = (fetchImpl as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    const [url] = calls[0] as [string];
    expect(decodeURIComponent(url)).toContain('actor->>id=eq.user-abc');
  });

  it("clamps limit to a sensible range", async () => {
    const fetchImpl = makeFetchRows([]);
    const handler = createAuditQueryHandler({
      hasAuditReadPermission: vi.fn().mockResolvedValue(true),
      fetchImpl,
    });
    const req = makeReq({
      method: "POST",
      body: { tenant_id: TENANT_A, limit: 9999 },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const calls = (fetchImpl as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    const [url] = calls[0] as [string];
    expect(url).toContain("limit=500");
  });
});
