/**
 * Audit-emit wiring tests.
 *
 * These tests verify that auth.* events are emitted at the four required
 * sites (per Audit Phase Batch 1 spec):
 *   1. /api/session  POST (event: login_success)  -> auth.session.started
 *   2. /api/session  POST (event: signup_success) -> auth.user.created
 *   3. /api/session  POST (event: login_failed)   -> auth.session.failed
 *   4. /api/session/switch_tenant                 -> auth.tenant.switched
 *   5. /api/service-tokens/issue                  -> authz.service_token.issued
 *
 * Each handler accepts an `emitAudit` dependency for direct injection — the
 * tests assert the call shape matches AuditEventBase + emit_helper contract.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createSessionHandler } from "./session";
import { createSwitchTenantHandler } from "./session/switch_tenant";
import { createIssueServiceTokenHandler } from "./service-tokens/issue";
import { makeReq, makeRes } from "./_lib/test-helpers";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
  SERVICE_TOKEN_SIGNING_SECRET: "test-signing-secret-32-bytes-min!!",
  ALLOWED_REDIRECT_ORIGINS: "https://app.bsvibe.dev",
};

const USER_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiJ1c2VyLWFiYyIsImVtYWlsIjoiYUBiLmMiLCJleHAiOjk5OTk5OTk5OTl9." +
  "sig";

describe("audit emit wiring", () => {
  let envBackup: NodeJS.ProcessEnv;

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });

  afterEach(() => {
    process.env = envBackup;
  });

  it("POST /api/session with event=login_success emits auth.session.started", async () => {
    const emitAudit = vi.fn().mockResolvedValue({ ok: true, eventId: "x" });
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
      emitAudit,
    });
    const req = makeReq({
      method: "POST",
      body: {
        refresh_token: "rt-abc",
        event: "login_success",
        user_id: "user-abc",
        email: "u@example.com",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect(emitAudit).toHaveBeenCalledTimes(1);
    const [, input] = emitAudit.mock.calls[0];
    expect(input.eventType).toBe("auth.session.started");
    expect(input.actor).toEqual({
      type: "user",
      id: "user-abc",
      email: "u@example.com",
    });
    expect(input.data).toEqual({ method: "password" });
  });

  it("POST /api/session with event=signup_success emits auth.user.created", async () => {
    const emitAudit = vi.fn().mockResolvedValue({ ok: true, eventId: "x" });
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
      emitAudit,
    });
    const req = makeReq({
      method: "POST",
      body: {
        refresh_token: "rt-abc",
        event: "signup_success",
        user_id: "user-new",
        email: "new@example.com",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect(emitAudit).toHaveBeenCalledTimes(1);
    const [, input] = emitAudit.mock.calls[0];
    expect(input.eventType).toBe("auth.user.created");
    expect(input.actor.id).toBe("user-new");
  });

  it("POST /api/session with event=login_failed emits auth.session.failed (no cookie)", async () => {
    const emitAudit = vi.fn().mockResolvedValue({ ok: true, eventId: "x" });
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
      emitAudit,
    });
    const req = makeReq({
      method: "POST",
      body: {
        event: "login_failed",
        email: "wrong@example.com",
        reason: "invalid_credentials",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(204);
    // Cookie must NOT be set on a failed login.
    expect(captured.headers["Set-Cookie"]).toBeUndefined();
    expect(emitAudit).toHaveBeenCalledTimes(1);
    const [, input] = emitAudit.mock.calls[0];
    expect(input.eventType).toBe("auth.session.failed");
    expect(input.data).toEqual({
      email: "wrong@example.com",
      reason: "invalid_credentials",
    });
    expect(input.actor.type).toBe("system");
  });

  it("POST /api/session without event field does NOT emit (back-compat)", async () => {
    const emitAudit = vi.fn().mockResolvedValue({ ok: true, eventId: "x" });
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
      emitAudit,
    });
    const req = makeReq({
      method: "POST",
      body: { refresh_token: "rt-abc" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect(emitAudit).not.toHaveBeenCalled();
  });

  it("/api/session/switch_tenant emits auth.tenant.switched", async () => {
    const getMembership = vi.fn().mockResolvedValue("admin");
    const emitAudit = vi.fn().mockResolvedValue({ ok: true, eventId: "x" });
    const handler = createSwitchTenantHandler({ getMembership, emitAudit });
    const req = makeReq({
      method: "POST",
      body: { tenant_id: "tenant-xyz" },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect(emitAudit).toHaveBeenCalledTimes(1);
    const [, input] = emitAudit.mock.calls[0];
    expect(input.eventType).toBe("auth.tenant.switched");
    expect(input.tenantId).toBe("tenant-xyz");
    expect(input.actor).toEqual({ type: "user", id: "user-abc" });
    expect(input.data).toMatchObject({
      to_tenant_id: "tenant-xyz",
      role: "admin",
    });
  });

  it("/api/service-tokens/issue emits authz.service_token.issued", async () => {
    const getMembership = vi.fn().mockResolvedValue("owner");
    const verifyAccessToken = vi.fn().mockResolvedValue("user-abc");
    const emitAudit = vi.fn().mockResolvedValue({ ok: true, eventId: "x" });
    const handler = createIssueServiceTokenHandler({
      getMembership,
      verifyAccessToken,
      emitAudit,
    });
    const req = makeReq({
      method: "POST",
      body: {
        audience: "bsage",
        scope: ["bsage.read", "bsage.write"],
        tenant_id: "tenant-1",
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect(emitAudit).toHaveBeenCalledTimes(1);
    const [, input] = emitAudit.mock.calls[0];
    expect(input.eventType).toBe("authz.service_token.issued");
    expect(input.tenantId).toBe("tenant-1");
    expect(input.actor).toEqual({ type: "user", id: "user-abc" });
    expect(input.data).toMatchObject({
      audience: "bsage",
      scope: ["bsage.read", "bsage.write"],
    });
  });
});
