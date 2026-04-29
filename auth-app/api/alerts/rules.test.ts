import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createAlertRulesHandler } from "./rules";
import { makeReq, makeRes } from "../_lib/test-helpers";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
};

// Token for user "user-abc" (sub claim only — signature not verified by these
// handlers, mirroring api/audit/query).
const USER_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiJ1c2VyLWFiYyIsImV4cCI6OTk5OTk5OTk5OX0." +
  "sig";

const TENANT_ID = "00000000-0000-0000-0000-0000000000aa";
const RULE_ID = "11111111-1111-1111-1111-111111111111";

const validRule = {
  name: "audit-brute-force",
  event_pattern: "auth.session.failed",
  severity: "critical",
  channel: "telegram",
  config: { chat_id: "-100" },
  enabled: true,
};

function makeFetchOk(body: unknown, status = 200) {
  return vi.fn(async () =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }),
  ) as unknown as typeof fetch;
}

describe("alerts/rules handler — list (GET)", () => {
  let envBackup: NodeJS.ProcessEnv;
  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });
  afterEach(() => {
    process.env = envBackup;
  });

  it("405 on unsupported method", async () => {
    const handler = createAlertRulesHandler({
      hasAlertPermission: vi.fn(),
      fetchImpl: makeFetchOk([]),
    });
    const req = makeReq({ method: "PUT", headers: { authorization: `Bearer ${USER_TOKEN}` } });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("401 without Authorization", async () => {
    const handler = createAlertRulesHandler({
      hasAlertPermission: vi.fn(),
      fetchImpl: makeFetchOk([]),
    });
    const req = makeReq({ method: "GET", query: { tenant_id: TENANT_ID } });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("400 when tenant_id missing", async () => {
    const handler = createAlertRulesHandler({
      hasAlertPermission: vi.fn(),
      fetchImpl: makeFetchOk([]),
    });
    const req = makeReq({
      method: "GET",
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("403 when permission denied", async () => {
    const hasAlertPermission = vi.fn().mockResolvedValue(false);
    const handler = createAlertRulesHandler({
      hasAlertPermission,
      fetchImpl: makeFetchOk([]),
    });
    const req = makeReq({
      method: "GET",
      query: { tenant_id: TENANT_ID },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
    expect(hasAlertPermission).toHaveBeenCalledWith(
      expect.anything(),
      "user-abc",
      TENANT_ID,
      "core.alerts.read",
      expect.anything(),
    );
  });

  it("200 returns rules from Supabase", async () => {
    const fakeRules = [
      { id: RULE_ID, tenant_id: TENANT_ID, ...validRule, created_at: "x", updated_at: "x" },
    ];
    const hasAlertPermission = vi.fn().mockResolvedValue(true);
    const fetchImpl = makeFetchOk(fakeRules);
    const handler = createAlertRulesHandler({ hasAlertPermission, fetchImpl });
    const req = makeReq({
      method: "GET",
      query: { tenant_id: TENANT_ID },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect(captured.body).toEqual({ rules: fakeRules });
    // permission probed for read scope
    expect(hasAlertPermission).toHaveBeenCalledWith(
      expect.anything(),
      "user-abc",
      TENANT_ID,
      "core.alerts.read",
      expect.anything(),
    );
  });
});

describe("alerts/rules handler — create (POST)", () => {
  let envBackup: NodeJS.ProcessEnv;
  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });
  afterEach(() => {
    process.env = envBackup;
  });

  it("400 when severity invalid", async () => {
    const handler = createAlertRulesHandler({
      hasAlertPermission: vi.fn().mockResolvedValue(true),
      fetchImpl: makeFetchOk([]),
    });
    const req = makeReq({
      method: "POST",
      body: { tenant_id: TENANT_ID, ...validRule, severity: "loud" },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("400 when event_pattern grammar invalid", async () => {
    const handler = createAlertRulesHandler({
      hasAlertPermission: vi.fn().mockResolvedValue(true),
      fetchImpl: makeFetchOk([]),
    });
    const req = makeReq({
      method: "POST",
      body: { tenant_id: TENANT_ID, ...validRule, event_pattern: "Auth.Bad" },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("403 when manage permission denied", async () => {
    const handler = createAlertRulesHandler({
      hasAlertPermission: vi.fn().mockResolvedValue(false),
      fetchImpl: makeFetchOk([]),
    });
    const req = makeReq({
      method: "POST",
      body: { tenant_id: TENANT_ID, ...validRule },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
  });

  it("201 inserts and returns the new rule", async () => {
    const inserted = {
      id: RULE_ID,
      tenant_id: TENANT_ID,
      ...validRule,
      created_at: "2026-04-28T00:00:00Z",
      updated_at: "2026-04-28T00:00:00Z",
    };
    const hasAlertPermission = vi.fn().mockResolvedValue(true);
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify([inserted]), {
        status: 201,
        headers: { "content-type": "application/json" },
      }),
    ) as unknown as typeof fetch;
    const handler = createAlertRulesHandler({ hasAlertPermission, fetchImpl });
    const req = makeReq({
      method: "POST",
      body: { tenant_id: TENANT_ID, ...validRule },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(201);
    expect((captured.body as { rule: unknown }).rule).toEqual(inserted);
    expect(hasAlertPermission).toHaveBeenCalledWith(
      expect.anything(),
      "user-abc",
      TENANT_ID,
      "core.alerts.manage",
      expect.anything(),
    );
  });

  it("supports trailing wildcard event_pattern", async () => {
    const inserted = {
      id: RULE_ID,
      tenant_id: TENANT_ID,
      ...validRule,
      event_pattern: "auth.*",
      created_at: "x",
      updated_at: "x",
    };
    const handler = createAlertRulesHandler({
      hasAlertPermission: vi.fn().mockResolvedValue(true),
      fetchImpl: vi.fn(async () =>
        new Response(JSON.stringify([inserted]), {
          status: 201,
          headers: { "content-type": "application/json" },
        }),
      ) as unknown as typeof fetch,
    });
    const req = makeReq({
      method: "POST",
      body: { tenant_id: TENANT_ID, ...validRule, event_pattern: "auth.*" },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(201);
  });
});

describe("alerts/rules handler — patch (PATCH)", () => {
  let envBackup: NodeJS.ProcessEnv;
  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });
  afterEach(() => {
    process.env = envBackup;
  });

  it("400 when route id missing", async () => {
    const handler = createAlertRulesHandler({
      hasAlertPermission: vi.fn().mockResolvedValue(true),
      fetchImpl: makeFetchOk([]),
    });
    const req = makeReq({
      method: "PATCH",
      body: { tenant_id: TENANT_ID, enabled: false },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("404 when row not found", async () => {
    const handler = createAlertRulesHandler({
      hasAlertPermission: vi.fn().mockResolvedValue(true),
      fetchImpl: makeFetchOk([], 200),
    });
    const req = makeReq({
      method: "PATCH",
      query: { id: RULE_ID },
      body: { tenant_id: TENANT_ID, enabled: false },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(404);
  });

  it("200 updates enabled flag", async () => {
    const updated = {
      id: RULE_ID,
      tenant_id: TENANT_ID,
      ...validRule,
      enabled: false,
      created_at: "x",
      updated_at: "y",
    };
    const handler = createAlertRulesHandler({
      hasAlertPermission: vi.fn().mockResolvedValue(true),
      fetchImpl: makeFetchOk([updated]),
    });
    const req = makeReq({
      method: "PATCH",
      query: { id: RULE_ID },
      body: { tenant_id: TENANT_ID, enabled: false },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect((captured.body as { rule: { enabled: boolean } }).rule.enabled).toBe(false);
  });

  it("400 when patch body has no fields", async () => {
    const handler = createAlertRulesHandler({
      hasAlertPermission: vi.fn().mockResolvedValue(true),
      fetchImpl: makeFetchOk([]),
    });
    const req = makeReq({
      method: "PATCH",
      query: { id: RULE_ID },
      body: { tenant_id: TENANT_ID },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });
});

describe("alerts/rules handler — delete (DELETE)", () => {
  let envBackup: NodeJS.ProcessEnv;
  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });
  afterEach(() => {
    process.env = envBackup;
  });

  it("404 when row not found", async () => {
    const handler = createAlertRulesHandler({
      hasAlertPermission: vi.fn().mockResolvedValue(true),
      fetchImpl: makeFetchOk([]),
    });
    const req = makeReq({
      method: "DELETE",
      query: { id: RULE_ID, tenant_id: TENANT_ID },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(404);
  });

  it("204 when row deleted", async () => {
    const handler = createAlertRulesHandler({
      hasAlertPermission: vi.fn().mockResolvedValue(true),
      fetchImpl: makeFetchOk([{ id: RULE_ID }]),
    });
    const req = makeReq({
      method: "DELETE",
      query: { id: RULE_ID, tenant_id: TENANT_ID },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(204);
  });
});
