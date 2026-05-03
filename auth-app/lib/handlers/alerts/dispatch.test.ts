import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createDispatchHandler } from "./dispatch";
import { makeReq, makeRes, signTestToken } from "../_lib/test-helpers";
import type { AlertRoute } from "../_lib/alert-routes";

const SIGNING_SECRET = "test-signing-secret-32-bytes-min!!";
const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
  SERVICE_TOKEN_SIGNING_SECRET: SIGNING_SECRET,
};

const TENANT_ID = "00000000-0000-0000-0000-0000000000aa";

async function makeServiceToken(scope = "alerts.dispatch", audience = "bsvibe-auth") {
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

const validEvent = {
  event_id: "11111111-1111-1111-1111-111111111111",
  event_type: "auth.session.failed",
  occurred_at: "2026-04-28T00:00:00.000Z",
  actor: { type: "user", id: "user-1" },
  tenant_id: TENANT_ID,
  data: { severity: "critical", reason: "bad_password" },
};

function makeRoute(overrides: Partial<AlertRoute> = {}): AlertRoute {
  return {
    id: "22222222-2222-2222-2222-222222222222",
    tenant_id: TENANT_ID,
    name: "brute-force",
    event_pattern: "auth.session.failed",
    severity: "warning",
    channel: "telegram",
    config: { chat_id: "-100" },
    enabled: true,
    created_at: "2026-04-28T00:00:00Z",
    updated_at: "2026-04-28T00:00:00Z",
    ...overrides,
  };
}

describe("alerts/dispatch handler", () => {
  let envBackup: NodeJS.ProcessEnv;
  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });
  afterEach(() => {
    process.env = envBackup;
  });

  it("405 for non-POST", async () => {
    const handler = createDispatchHandler({ loadRoutes: vi.fn() });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("401 without Authorization", async () => {
    const handler = createDispatchHandler({ loadRoutes: vi.fn() });
    const req = makeReq({ method: "POST", body: validEvent });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("403 when scope missing", async () => {
    const handler = createDispatchHandler({ loadRoutes: vi.fn() });
    const token = await makeServiceToken("audit.write");
    const req = makeReq({
      method: "POST",
      body: validEvent,
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
  });

  it("403 when audience wrong", async () => {
    const handler = createDispatchHandler({ loadRoutes: vi.fn() });
    const token = await makeServiceToken("alerts.dispatch", "bsage");
    const req = makeReq({
      method: "POST",
      body: validEvent,
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
  });

  it("400 when event invalid", async () => {
    const handler = createDispatchHandler({ loadRoutes: vi.fn() });
    const token = await makeServiceToken();
    const req = makeReq({
      method: "POST",
      body: { ...validEvent, event_type: "BAD" },
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("returns matched_rules: 0 when no rules match", async () => {
    const loadRoutes = vi.fn().mockResolvedValue([
      makeRoute({ event_pattern: "billing.charge.failed" }),
    ]);
    const handler = createDispatchHandler({ loadRoutes });
    const token = await makeServiceToken();
    const req = makeReq({
      method: "POST",
      body: validEvent,
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect((captured.body as { matched_rules: number }).matched_rules).toBe(0);
  });

  it("matches exact event_pattern + severity ladder", async () => {
    const matching = makeRoute({ event_pattern: "auth.session.failed", severity: "warning" });
    const ignoredHigher = makeRoute({
      id: "33333333-3333-3333-3333-333333333333",
      severity: "critical",
      event_pattern: "auth.session.failed",
    });
    const loadRoutes = vi.fn().mockResolvedValue([matching, ignoredHigher]);
    const handler = createDispatchHandler({ loadRoutes });
    const token = await makeServiceToken();

    // Event has severity = "critical" → both warning AND critical rules fire.
    const req = makeReq({
      method: "POST",
      body: validEvent,
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect((captured.body as { matched_rules: number }).matched_rules).toBe(2);
  });

  it("does NOT fire warning rule for info-severity event", async () => {
    const route = makeRoute({ severity: "warning", event_pattern: "auth.session.failed" });
    const loadRoutes = vi.fn().mockResolvedValue([route]);
    const handler = createDispatchHandler({ loadRoutes });
    const token = await makeServiceToken();
    const req = makeReq({
      method: "POST",
      body: { ...validEvent, data: {} }, // severity defaults to info
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect((captured.body as { matched_rules: number }).matched_rules).toBe(0);
  });

  it("supports trailing wildcard in event_pattern", async () => {
    const route = makeRoute({ event_pattern: "auth.*", severity: "info" });
    const loadRoutes = vi.fn().mockResolvedValue([route]);
    const handler = createDispatchHandler({ loadRoutes });
    const token = await makeServiceToken();
    const req = makeReq({
      method: "POST",
      body: { ...validEvent, data: {} }, // severity → info, route min = info
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    const body = captured.body as { matched_rules: number; deliveries: unknown[] };
    expect(body.matched_rules).toBe(1);
    expect(body.deliveries).toHaveLength(1);
  });

  it("ignores disabled rules", async () => {
    const route = makeRoute({ event_pattern: "auth.session.failed", severity: "info", enabled: false });
    const loadRoutes = vi.fn().mockResolvedValue([route]);
    const handler = createDispatchHandler({ loadRoutes });
    const token = await makeServiceToken();
    const req = makeReq({
      method: "POST",
      body: validEvent,
      headers: { authorization: `Bearer ${token}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect((captured.body as { matched_rules: number }).matched_rules).toBe(0);
  });
});
