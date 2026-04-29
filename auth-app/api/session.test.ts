import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createSessionHandler } from "./session";
import { makeReq, makeRes, getSetCookieHeader } from "./_lib/test-helpers";
import type { Tenant } from "./_lib/tenants";

const mockTenants: Tenant[] = [
  { id: "p1", name: "Alice", type: "personal", role: "owner", plan: "pro" },
  { id: "o1", name: "ACME", type: "org", role: "admin", plan: "team" },
];

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
  USER_JWT_SECRET: "test-user-jwt-secret",
  USER_JWT_ISSUER: "https://test.supabase.co/auth/v1",
  USER_JWT_AUDIENCE: "authenticated",
  ALLOWED_REDIRECT_ORIGINS: "https://app.bsvibe.dev",
};

function decodeJwtPayload<T = Record<string, unknown>>(token: string): T {
  const [, payload] = token.split(".");
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as T;
}

describe("session handler", () => {
  let envBackup: NodeJS.ProcessEnv;

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });

  afterEach(() => {
    process.env = envBackup;
  });

  it("OPTIONS returns 204 with CORS headers", async () => {
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
    });
    const req = makeReq({
      method: "OPTIONS",
      headers: { origin: "https://app.bsvibe.dev" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(204);
    expect(captured.headers["Access-Control-Allow-Origin"]).toBe(
      "https://app.bsvibe.dev",
    );
    expect(captured.headers["Access-Control-Allow-Credentials"]).toBe("true");
  });

  it("POST sets session cookie when refresh_token is provided", async () => {
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
    });
    const req = makeReq({
      method: "POST",
      body: { refresh_token: "rt-123" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect(captured.body).toEqual({ ok: true });
    const setCookie = getSetCookieHeader(captured);
    expect(setCookie).toMatch(/bsvibe_session=rt-123/);
    expect(setCookie).toMatch(/HttpOnly/);
    expect(setCookie).toMatch(/Domain=\.bsvibe\.dev/);
  });

  it("POST returns 400 when refresh_token is missing", async () => {
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
    });
    const req = makeReq({ method: "POST", body: {} });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("GET returns 401 when no session cookie", async () => {
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
    });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("GET refreshes tokens, attaches tenants[] + active_tenant_id", async () => {
    const supabaseTokenResponse = {
      access_token:
        // Header: {"alg":"HS256","typ":"JWT"}
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        // Payload: {"sub":"user-abc","email":"a@b.c","exp":9999999999}
        "eyJzdWIiOiJ1c2VyLWFiYyIsImVtYWlsIjoiYUBiLmMiLCJleHAiOjk5OTk5OTk5OTl9." +
        "sig",
      refresh_token: "rt-new",
      expires_in: 3600,
    };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => supabaseTokenResponse,
    });
    const listTenants = vi.fn().mockResolvedValue(mockTenants);

    const handler = createSessionHandler({
      listTenantsForUser: listTenants,
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const req = makeReq({
      method: "GET",
      cookies: { bsvibe_session: "rt-old" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as Record<string, unknown>;
    expect(typeof body.access_token).toBe("string");
    expect(body.refresh_token).toBe("rt-new");
    expect(body.expires_in).toBe(3600);
    expect(body.tenants).toEqual(mockTenants);
    expect(body.active_tenant_id).toBe("p1"); // personal preferred
    expect(listTenants).toHaveBeenCalledWith(
      expect.objectContaining({ url: baseEnv.SUPABASE_URL }),
      "user-abc",
      expect.anything(),
    );
    const setCookie = getSetCookieHeader(captured);
    expect(setCookie).toMatch(/bsvibe_session=rt-new/);
  });

  it("GET returns a BSVibe session JWT with active tenant claims", async () => {
    const supabaseTokenResponse = {
      access_token:
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzdWIiOiJ1c2VyLWFiYyIsImVtYWlsIjoiYUBiLmMiLCJleHAiOjk5OTk5OTk5OTl9." +
        "sig",
      refresh_token: "rt-new",
      expires_in: 3600,
    };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => supabaseTokenResponse,
    });
    const listTenants = vi.fn().mockResolvedValue(mockTenants);
    const handler = createSessionHandler({
      listTenantsForUser: listTenants,
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const req = makeReq({
      method: "GET",
      cookies: { bsvibe_session: "rt-old" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as Record<string, string>;
    expect(body.access_token).not.toBe(supabaseTokenResponse.access_token);
    const payload = decodeJwtPayload<{
      sub: string;
      email: string;
      active_tenant_id: string;
      app_metadata: { tenant_id: string; role: string };
      aud: string;
      iss: string;
    }>(body.access_token);
    expect(payload.sub).toBe("user-abc");
    expect(payload.email).toBe("a@b.c");
    expect(payload.active_tenant_id).toBe("p1");
    expect(payload.app_metadata).toEqual({ tenant_id: "p1", role: "owner" });
    expect(payload.aud).toBe("authenticated");
    expect(payload.iss).toBe("https://test.supabase.co/auth/v1");
  });

  it("GET clears cookie and returns 401 when refresh fails", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 401, json: async () => ({}) });
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
      fetchImpl: fetchMock as unknown as typeof fetch,
    });
    const req = makeReq({
      method: "GET",
      cookies: { bsvibe_session: "rt-old" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    const setCookie = getSetCookieHeader(captured);
    expect(setCookie).toMatch(/Max-Age=0/);
  });

  it("GET returns empty tenants[] and null active_tenant_id when listTenants fails (degrade gracefully)", async () => {
    const supabaseTokenResponse = {
      access_token:
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzdWIiOiJ1c2VyLXh5eiIsImVtYWlsIjoiYUBiLmMiLCJleHAiOjk5OTk5OTk5OTl9." +
        "sig",
      refresh_token: "rt-new",
      expires_in: 3600,
    };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => supabaseTokenResponse,
    });
    const listTenants = vi
      .fn()
      .mockRejectedValue(new Error("tenants_fetch_failed: 500"));

    const handler = createSessionHandler({
      listTenantsForUser: listTenants,
      fetchImpl: fetchMock as unknown as typeof fetch,
    });

    const req = makeReq({
      method: "GET",
      cookies: { bsvibe_session: "rt-old" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as Record<string, unknown>;
    expect(body.tenants).toEqual([]);
    expect(body.active_tenant_id).toBeNull();
  });

  it("DELETE clears cookie", async () => {
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
    });
    const req = makeReq({ method: "DELETE" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const setCookie = getSetCookieHeader(captured);
    expect(setCookie).toMatch(/Max-Age=0/);
  });

  it("returns 405 for unsupported methods", async () => {
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
    });
    const req = makeReq({ method: "PATCH" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("returns 500 when supabase env not configured", async () => {
    delete process.env.SUPABASE_URL;
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
    });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(500);
  });
});
