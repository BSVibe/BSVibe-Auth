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
  USER_JWT_ISSUER: "https://test.supabase.co/auth/v1",
  USER_JWT_AUDIENCE: "authenticated",
  ALLOWED_REDIRECT_ORIGINS: "https://app.bsvibe.dev",
};

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
    const supabaseTokenResponse = {
      access_token:
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzdWIiOiJ1c2VyLXBvc3QiLCJlbWFpbCI6InBvc3RAZXhhbXBsZS5kZXYiLCJleHAiOjk5OTk5OTk5OTl9." +
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
      method: "POST",
      body: { refresh_token: "rt-123" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = captured.body as Record<string, unknown>;
    expect(body.refresh_token).toBe("rt-new");
    expect(body.expires_in).toBe(3600);
    expect(body.tenants).toEqual(mockTenants);
    expect(body.active_tenant_id).toBe("p1");
    // Tier 3.2: /api/session returns the raw Supabase access_token
    // unmodified — the wrapped HS256 re-signer was retired.
    expect(body.access_token).toBe(supabaseTokenResponse.access_token);
    const setCookie = getSetCookieHeader(captured);
    expect(setCookie).toMatch(/bsvibe_session=rt-new/);
    expect(setCookie).toMatch(/HttpOnly/);
    expect(setCookie).toMatch(/Domain=\.bsvibe\.dev/);
  });

  it("POST clears cookie and returns 401 when refresh token exchange fails", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 401, json: async () => ({}) });
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
      fetchImpl: fetchMock as unknown as typeof fetch,
    });
    const req = makeReq({
      method: "POST",
      body: { refresh_token: "rt-bad" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toEqual({ error: "Session expired" });
    expect(getSetCookieHeader(captured)).toMatch(/Max-Age=0/);
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

  it("GET returns 401 when no session cookie and no Authorization header", async () => {
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
    });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("GET (bearer fallback) validates Authorization token via Supabase /auth/v1/user and returns tenants", async () => {
    // Bearer-mode clients (token-mode SPAs / e2e) don't have the
    // bsvibe_session cookie. They send the Supabase access_token in
    // Authorization header instead. Auth-app validates with Supabase
    // and returns the same shape (without rotating refresh_token).
    const bearer =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
      // Payload: {"sub":"user-abc","email":"a@b.c","exp":9999999999}
      "eyJzdWIiOiJ1c2VyLWFiYyIsImVtYWlsIjoiYUBiLmMiLCJleHAiOjk5OTk5OTk5OTl9." +
      "sig";
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: "user-abc" }),
    });
    const listTenants = vi.fn().mockResolvedValue(mockTenants);

    const handler = createSessionHandler({
      listTenantsForUser: listTenants,
      fetchImpl: fetchMock as unknown as typeof fetch,
    });
    const req = makeReq({
      method: "GET",
      headers: { authorization: `Bearer ${bearer}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as Record<string, unknown>;
    expect(body.access_token).toBe(bearer);
    expect(body.refresh_token).toBe("");
    expect(body.tenants).toEqual(mockTenants);
    expect(body.active_tenant_id).toBe("p1");
    expect(fetchMock).toHaveBeenCalledWith(
      `${baseEnv.SUPABASE_URL}/auth/v1/user`,
      expect.objectContaining({
        headers: expect.objectContaining({
          apikey: baseEnv.SUPABASE_ANON_KEY,
          Authorization: `Bearer ${bearer}`,
        }),
      }),
    );
  });

  it("GET (bearer fallback) returns 401 when Supabase rejects the token", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, json: async () => ({}) });
    const handler = createSessionHandler({
      listTenantsForUser: vi.fn(),
      fetchImpl: fetchMock as unknown as typeof fetch,
    });
    const req = makeReq({
      method: "GET",
      headers: { authorization: "Bearer bad-token" },
    });
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

  it("GET returns the raw Supabase access_token (Tier 3.2 — wrapper retired)", async () => {
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
    const body = captured.body as Record<string, unknown>;
    // Tier 3.2: the wrapped HS256 re-signer (issueSessionJwt) is gone —
    // /api/session returns the raw Supabase access_token byte-for-byte.
    // The active tenant rides as the response-body `active_tenant_id`
    // field and the `X-Active-Tenant` request header, never a JWT claim.
    expect(body.access_token).toBe(supabaseTokenResponse.access_token);
    expect(body.active_tenant_id).toBe("p1");
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

  describe("POST tenant provisioning hook", () => {
    const supabaseTokenResponse = {
      access_token:
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "eyJzdWIiOiJ1c2VyLXBvc3QiLCJlbWFpbCI6InBvc3RAZXhhbXBsZS5kZXYiLCJleHAiOjk5OTk5OTk5OTl9." +
        "sig",
      refresh_token: "rt-new",
      expires_in: 3600,
    };

    function setup(opts: {
      event: "signup_success" | "login_success";
      ensureTenant?: ReturnType<typeof vi.fn>;
      emit?: ReturnType<typeof vi.fn>;
    }) {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => supabaseTokenResponse,
      });
      const ensureTenant =
        opts.ensureTenant ?? vi.fn().mockResolvedValue("tenant-new");
      const emit = opts.emit ?? vi.fn().mockResolvedValue({ ok: true });
      const handler = createSessionHandler({
        listTenantsForUser: vi.fn().mockResolvedValue(mockTenants),
        ensurePersonalTenant: ensureTenant as unknown as (
          ...args: unknown[]
        ) => Promise<string>,
        fetchImpl: fetchMock as unknown as typeof fetch,
        emitAudit: emit as unknown as Parameters<
          typeof createSessionHandler
        >[0]["emitAudit"],
      });
      return { handler, ensureTenant, emit };
    }

    it("calls ensurePersonalTenant on signup_success with email-prefix display name", async () => {
      const { handler, ensureTenant, emit } = setup({ event: "signup_success" });
      const req = makeReq({
        method: "POST",
        body: {
          refresh_token: "rt",
          event: "signup_success",
          user_id: "user-new",
          email: "alice@example.dev",
        },
      });
      const { res, captured } = makeRes();
      await handler(req, res);
      expect(captured.statusCode).toBe(200);
      expect(ensureTenant).toHaveBeenCalledTimes(1);
      expect(ensureTenant).toHaveBeenCalledWith(
        expect.objectContaining({
          url: baseEnv.SUPABASE_URL,
          serviceRoleKey: baseEnv.SUPABASE_SERVICE_ROLE_KEY,
        }),
        "user-new",
        "alice",
        expect.anything(),
      );
      expect(emit).toHaveBeenCalledTimes(1);
    });

    it("calls ensurePersonalTenant on login_success (idempotent path)", async () => {
      const { handler, ensureTenant } = setup({ event: "login_success" });
      const req = makeReq({
        method: "POST",
        body: {
          refresh_token: "rt",
          event: "login_success",
          user_id: "user-existing",
          email: "bob@example.dev",
        },
      });
      const { res, captured } = makeRes();
      await handler(req, res);
      expect(captured.statusCode).toBe(200);
      expect(ensureTenant).toHaveBeenCalledWith(
        expect.anything(),
        "user-existing",
        "bob",
        expect.anything(),
      );
    });

    it("does not block 200 + cookie when ensurePersonalTenant rejects", async () => {
      const ensureTenant = vi.fn().mockRejectedValue(new Error("rpc 500"));
      const { handler, emit } = setup({
        event: "login_success",
        ensureTenant,
      });
      const req = makeReq({
        method: "POST",
        body: {
          refresh_token: "rt",
          event: "login_success",
          user_id: "user-x",
          email: "x@y.z",
        },
      });
      const { res, captured } = makeRes();
      await handler(req, res);
      expect(captured.statusCode).toBe(200);
      expect(getSetCookieHeader(captured)).toMatch(/bsvibe_session=rt-new/);
      // audit emit still runs after the swallowed RPC failure.
      expect(emit).toHaveBeenCalledTimes(1);
    });

    it("does not call ensurePersonalTenant when no event flag is set", async () => {
      const { handler, ensureTenant } = setup({ event: "login_success" });
      const req = makeReq({
        method: "POST",
        body: { refresh_token: "rt", user_id: "u" },
      });
      const { res, captured } = makeRes();
      await handler(req, res);
      expect(captured.statusCode).toBe(200);
      expect(ensureTenant).not.toHaveBeenCalled();
    });

    it("passes null display name when email is missing", async () => {
      const { handler, ensureTenant } = setup({ event: "login_success" });
      const req = makeReq({
        method: "POST",
        body: {
          refresh_token: "rt",
          event: "login_success",
          user_id: "user-no-email",
        },
      });
      const { res } = makeRes();
      await handler(req, res);
      expect(ensureTenant).toHaveBeenCalledWith(
        expect.anything(),
        "user-no-email",
        null,
        expect.anything(),
      );
    });
  });
});
