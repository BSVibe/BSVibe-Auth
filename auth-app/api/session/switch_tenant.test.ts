import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createSwitchTenantHandler } from "./switch_tenant";
import { makeReq, makeRes, getSetCookieHeader } from "../_lib/test-helpers";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
};

// Token for user "user-abc" — header.payload.sig
const VALID_USER_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiJ1c2VyLWFiYyIsImVtYWlsIjoiYUBiLmMiLCJleHAiOjk5OTk5OTk5OTl9." +
  "sig";

describe("switch_tenant handler", () => {
  let envBackup: NodeJS.ProcessEnv;

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });

  afterEach(() => {
    process.env = envBackup;
  });

  it("returns 405 for non-POST", async () => {
    const handler = createSwitchTenantHandler({ getMembership: vi.fn() });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("returns 401 when no Authorization header", async () => {
    const handler = createSwitchTenantHandler({ getMembership: vi.fn() });
    const req = makeReq({ method: "POST", body: { tenant_id: "t1" } });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("returns 400 when tenant_id missing", async () => {
    const handler = createSwitchTenantHandler({ getMembership: vi.fn() });
    const req = makeReq({
      method: "POST",
      body: {},
      headers: { authorization: `Bearer ${VALID_USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("returns 403 when user is not a member of requested tenant", async () => {
    const getMembership = vi.fn().mockResolvedValue(null);
    const handler = createSwitchTenantHandler({ getMembership });
    const req = makeReq({
      method: "POST",
      body: { tenant_id: "t-not-mine" },
      headers: { authorization: `Bearer ${VALID_USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
    expect(getMembership).toHaveBeenCalledWith(
      expect.objectContaining({ url: baseEnv.SUPABASE_URL }),
      "user-abc",
      "t-not-mine",
      expect.anything(),
    );
  });

  it("sets active_tenant cookie and returns 200 when membership exists", async () => {
    const getMembership = vi.fn().mockResolvedValue("admin");
    const handler = createSwitchTenantHandler({ getMembership });
    const req = makeReq({
      method: "POST",
      body: { tenant_id: "t-mine" },
      headers: { authorization: `Bearer ${VALID_USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as Record<string, unknown>;
    expect(body.active_tenant_id).toBe("t-mine");
    expect(body.role).toBe("admin");

    const setCookie = getSetCookieHeader(captured);
    expect(setCookie).toMatch(/bsvibe_active_tenant=t-mine/);
    expect(setCookie).toMatch(/HttpOnly/);
    expect(setCookie).toMatch(/Domain=\.bsvibe\.dev/);
  });

  it("returns 401 when access_token cannot be decoded", async () => {
    const handler = createSwitchTenantHandler({ getMembership: vi.fn() });
    const req = makeReq({
      method: "POST",
      body: { tenant_id: "t1" },
      headers: { authorization: "Bearer not-a-jwt" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("returns 500 when supabase env not configured", async () => {
    delete process.env.SUPABASE_URL;
    const handler = createSwitchTenantHandler({ getMembership: vi.fn() });
    const req = makeReq({
      method: "POST",
      body: { tenant_id: "t1" },
      headers: { authorization: `Bearer ${VALID_USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(500);
  });
});
