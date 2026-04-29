import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createAuditEventsHandler } from "./events";
import { makeReq, makeRes } from "../_lib/test-helpers";
import { signTestToken } from "../_lib/test-helpers";

const SIGNING_SECRET = "test-signing-secret-32-bytes-min!!";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
  SERVICE_TOKEN_SIGNING_SECRET: SIGNING_SECRET,
};

async function makeServiceToken(scope = "audit.write", audience = "bsvibe-auth") {
  return signTestToken(SIGNING_SECRET, {
    iss: "https://auth.bsvibe.dev",
    sub: "service:bsage",
    aud: audience,
    scope,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    token_type: "service",
  });
}

function makeFetchOk() {
  return vi.fn(async () =>
    new Response(null, { status: 201 }),
  ) as unknown as typeof fetch;
}

const validEvent = {
  event_id: "11111111-1111-1111-1111-111111111111",
  event_type: "auth.session.started",
  occurred_at: "2026-04-27T12:00:00.000Z",
  actor: { type: "user", id: "user-1" },
  tenant_id: "00000000-0000-0000-0000-0000000000aa",
  data: { method: "password" },
};

describe("audit/events handler", () => {
  let envBackup: NodeJS.ProcessEnv;

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });

  afterEach(() => {
    process.env = envBackup;
  });

  it("returns 405 for non-POST", async () => {
    const handler = createAuditEventsHandler({ fetchImpl: makeFetchOk() });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("returns 401 without Authorization", async () => {
    const handler = createAuditEventsHandler({ fetchImpl: makeFetchOk() });
    const req = makeReq({ method: "POST", body: { events: [validEvent] } });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("returns 401 when token signature is invalid", async () => {
    const handler = createAuditEventsHandler({ fetchImpl: makeFetchOk() });
    const req = makeReq({
      method: "POST",
      body: { events: [validEvent] },
      headers: { authorization: "Bearer not.a.valid.jwt" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("returns 403 when token lacks audit.write scope", async () => {
    const token = await makeServiceToken("something.else");
    const handler = createAuditEventsHandler({ fetchImpl: makeFetchOk() });
    const req = makeReq({
      method: "POST",
      body: { events: [validEvent] },
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
  });

  it("returns 400 when body has no events", async () => {
    const token = await makeServiceToken();
    const handler = createAuditEventsHandler({ fetchImpl: makeFetchOk() });
    const req = makeReq({
      method: "POST",
      body: {},
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("returns 400 when batch exceeds 100", async () => {
    const token = await makeServiceToken();
    const handler = createAuditEventsHandler({ fetchImpl: makeFetchOk() });
    const events = Array.from({ length: 101 }, (_, i) => ({
      ...validEvent,
      event_id: `00000000-0000-0000-0000-${String(i).padStart(12, "0")}`,
    }));
    const req = makeReq({
      method: "POST",
      body: { events },
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("accepts a valid batch and POSTs rows to Supabase with idempotency", async () => {
    const token = await makeServiceToken();
    const fetchImpl = makeFetchOk();
    const handler = createAuditEventsHandler({ fetchImpl });
    const req = makeReq({
      method: "POST",
      body: { events: [validEvent] },
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as { accepted: number; rejected: unknown[] };
    expect(body.accepted).toBe(1);
    expect(body.rejected).toEqual([]);

    const calls = (fetchImpl as unknown as { mock: { calls: unknown[][] } }).mock.calls;
    expect(calls).toHaveLength(1);
    const [url, init] = calls[0] as [string, RequestInit];
    expect(url).toBe("https://test.supabase.co/rest/v1/audit_events");
    const headers = init.headers as Record<string, string>;
    expect(headers.apikey).toBe("service-role-key");
    expect(headers.Prefer).toContain("resolution=ignore-duplicates");
    const rows = JSON.parse(init.body as string) as Array<{ id: string }>;
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(validEvent.event_id);
  });

  it("rejects malformed events but still ingests valid ones", async () => {
    const token = await makeServiceToken();
    const fetchImpl = makeFetchOk();
    const handler = createAuditEventsHandler({ fetchImpl });
    const bad = { ...validEvent, event_id: "not-a-uuid" };
    const noType = { ...validEvent, event_id: "22222222-2222-2222-2222-222222222222", event_type: "" };
    const req = makeReq({
      method: "POST",
      body: { events: [validEvent, bad, noType] },
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = captured.body as { accepted: number; rejected: { event_id: string; reason: string }[] };
    expect(body.accepted).toBe(1);
    expect(body.rejected).toHaveLength(2);
    expect(body.rejected.find((r) => r.event_id === "not-a-uuid")?.reason).toMatch(/event_id|uuid/i);
    expect(
      body.rejected.find((r) => r.event_id === "22222222-2222-2222-2222-222222222222")?.reason,
    ).toMatch(/event_type/i);
  });

  it("returns 502 when upstream Supabase fails", async () => {
    const token = await makeServiceToken();
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify({ message: "boom" }), {
        status: 500,
        headers: { "content-type": "application/json" },
      }),
    ) as unknown as typeof fetch;
    const handler = createAuditEventsHandler({ fetchImpl });
    const req = makeReq({
      method: "POST",
      body: { events: [validEvent] },
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(502);
  });
});
