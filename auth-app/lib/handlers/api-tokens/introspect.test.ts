import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createIntrospectHandler } from "./introspect";
import { makeReq, makeRes } from "../_lib/test-helpers";
import {
  hashClientSecret,
  type OAuthClientRecord,
} from "../_lib/oauth-client";
import {
  generatePatJwt,
} from "../_lib/api-token";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
  SERVICE_TOKEN_SIGNING_SECRET: "test-signing-secret-32-bytes-min!!",
  SERVICE_TOKEN_ISSUER: "https://auth.bsvibe.dev",
};

const tenantId = "98aafacf-ac62-479f-b8ab-21c0fe4e113e";
const userId = "11111111-1111-1111-1111-111111111111";
const validClientId = "introspect-caller";
const validClientSecret = "long-random-client-secret-of-yours";

async function buildClientRecord(
  overrides: Partial<OAuthClientRecord> = {},
): Promise<OAuthClientRecord> {
  return {
    client_id: validClientId,
    client_type: "confidential",
    client_secret_hash: await hashClientSecret(validClientSecret),
    tenant_id: tenantId,
    allowed_audiences: ["bsgateway"],
    allowed_scopes: ["bsgateway:models:read"],
    revoked_at: null,
    ...overrides,
  };
}

function basicHeader(id: string, secret: string): string {
  return "Basic " + Buffer.from(`${id}:${secret}`).toString("base64");
}

describe("api-tokens/introspect", () => {
  let envBackup: NodeJS.ProcessEnv;

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });

  afterEach(() => {
    process.env = envBackup;
    vi.restoreAllMocks();
  });

  it("204 on OPTIONS preflight", async () => {
    const handler = createIntrospectHandler({ lookupClient: vi.fn() });
    const req = makeReq({ method: "OPTIONS" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(204);
  });

  it("405 on non-POST", async () => {
    const handler = createIntrospectHandler({ lookupClient: vi.fn() });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("401 invalid_client when no Basic auth", async () => {
    const handler = createIntrospectHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "token=anything",
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
    expect(captured.headers["WWW-Authenticate"]).toBeDefined();
  });

  it("401 invalid_client when secret wrong", async () => {
    const record = await buildClientRecord();
    const handler = createIntrospectHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
    });
    const req = makeReq({
      method: "POST",
      headers: {
        authorization: basicHeader(validClientId, "wrong"),
        "content-type": "application/x-www-form-urlencoded",
      },
      body: "token=bsv_sk_xxx",
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
  });

  it("401 invalid_client when client revoked", async () => {
    const record = await buildClientRecord({
      revoked_at: "2026-01-01T00:00:00Z",
    });
    const handler = createIntrospectHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
    });
    const req = makeReq({
      method: "POST",
      headers: {
        authorization: basicHeader(validClientId, validClientSecret),
        "content-type": "application/x-www-form-urlencoded",
      },
      body: "token=bsv_sk_xxx",
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("400 invalid_request when token missing", async () => {
    const record = await buildClientRecord();
    const handler = createIntrospectHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
    });
    const req = makeReq({
      method: "POST",
      headers: {
        authorization: basicHeader(validClientId, validClientSecret),
        "content-type": "application/x-www-form-urlencoded",
      },
      body: "",
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_request" });
  });

  it("active=false for malformed token (neither prefix nor JWT shape)", async () => {
    const record = await buildClientRecord();
    const handler = createIntrospectHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
      fetchImpl: vi.fn() as unknown as typeof fetch,
    });
    const req = makeReq({
      method: "POST",
      headers: {
        authorization: basicHeader(validClientId, validClientSecret),
        "content-type": "application/x-www-form-urlencoded",
      },
      body: "token=garbage",
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect(captured.body).toEqual({ active: false });
  });

  it("active=false for legacy bsv_sk_* opaque token (Tier 2 retirement)", async () => {
    // Regression guard: the bsv_sk_*/bsv_pk_* opaque-token branch was
    // retired in Tier 2 of the 2026-05 auth cleanup. Anything not JWT-shaped
    // now returns active=false without ever touching the database.
    const record = await buildClientRecord();
    const fetchImpl = vi.fn(async () =>
      new Response("[]", { status: 200 }),
    ) as unknown as typeof fetch;
    const handler = createIntrospectHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
      fetchImpl,
    });
    const req = makeReq({
      method: "POST",
      headers: {
        authorization: basicHeader(validClientId, validClientSecret),
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `token=${encodeURIComponent("bsv_sk_legacy")}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.body).toEqual({ active: false });
  });

  it("active=true for valid PAT JWT", async () => {
    const record = await buildClientRecord();
    const jti = "44444444-4444-4444-4444-444444444444";
    const tokenId = "55555555-5555-5555-5555-555555555555";
    const exp = Math.floor(Date.now() / 1000) + 600;
    const pat = await generatePatJwt(
      {
        sub: userId,
        tenant: tenantId,
        aud: ["bsgateway"],
        scope: ["bsgateway:models:read"],
        jti,
        exp,
      },
      {
        signingSecret: baseEnv.SERVICE_TOKEN_SIGNING_SECRET,
        issuer: baseEnv.SERVICE_TOKEN_ISSUER,
      },
    );

    const dbRow = {
      id: tokenId,
      user_id: userId,
      tenant_id: tenantId,
      type: "pat",
      audience: ["bsgateway"],
      scopes: ["bsgateway:models:read"],
      expires_at: new Date(exp * 1000).toISOString(),
      revoked_at: null,
    };

    const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
      if ((init?.method ?? "GET") === "GET") {
        return new Response(JSON.stringify([dbRow]), { status: 200 });
      }
      return new Response("", { status: 204 });
    }) as unknown as typeof fetch;

    const handler = createIntrospectHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
      fetchImpl,
    });
    const req = makeReq({
      method: "POST",
      headers: {
        authorization: basicHeader(validClientId, validClientSecret),
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `token=${encodeURIComponent(pat)}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = captured.body as Record<string, unknown>;
    expect(body.active).toBe(true);
    expect(body.sub).toBe(userId);
    expect(body.tenant).toBe(tenantId);
    expect(body.token_type).toBe("pat");
    expect(body.scope).toBe("bsgateway:models:read");
    expect(body.exp).toBe(exp);
    expect(body.jti).toBe(jti);
  });

  it("active=true response carries the holder's tenant role (Tier 5)", async () => {
    const record = await buildClientRecord();
    const jti = "66666666-6666-6666-6666-666666666666";
    const exp = Math.floor(Date.now() / 1000) + 600;
    const pat = await generatePatJwt(
      { sub: userId, tenant: tenantId, aud: ["bsgateway"], scope: ["bsgateway:models:read"], jti, exp },
      { signingSecret: baseEnv.SERVICE_TOKEN_SIGNING_SECRET, issuer: baseEnv.SERVICE_TOKEN_ISSUER },
    );
    const dbRow = {
      id: "77777777-7777-7777-7777-777777777777",
      user_id: userId,
      tenant_id: tenantId,
      type: "pat",
      audience: ["bsgateway"],
      scopes: ["bsgateway:models:read"],
      expires_at: new Date(exp * 1000).toISOString(),
      revoked_at: null,
    };
    // URL-aware mock: /tokens lookup vs /tenant_members role lookup.
    const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
      if ((init?.method ?? "GET") !== "GET") {
        return new Response("", { status: 204 });
      }
      if (url.includes("/tenant_members")) {
        return new Response(JSON.stringify([{ role: "admin" }]), { status: 200 });
      }
      return new Response(JSON.stringify([dbRow]), { status: 200 });
    }) as unknown as typeof fetch;

    const handler = createIntrospectHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
      fetchImpl,
    });
    const req = makeReq({
      method: "POST",
      headers: {
        authorization: basicHeader(validClientId, validClientSecret),
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `token=${encodeURIComponent(pat)}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = captured.body as Record<string, unknown>;
    expect(body.active).toBe(true);
    expect(body.role).toBe("admin");
  });

  it("active=true response omits role when holder has no membership", async () => {
    const record = await buildClientRecord();
    const jti = "88888888-8888-8888-8888-888888888888";
    const exp = Math.floor(Date.now() / 1000) + 600;
    const pat = await generatePatJwt(
      { sub: userId, tenant: tenantId, aud: ["bsgateway"], scope: ["bsgateway:models:read"], jti, exp },
      { signingSecret: baseEnv.SERVICE_TOKEN_SIGNING_SECRET, issuer: baseEnv.SERVICE_TOKEN_ISSUER },
    );
    const dbRow = {
      id: "99999999-9999-9999-9999-999999999999",
      user_id: userId,
      tenant_id: tenantId,
      type: "pat",
      audience: ["bsgateway"],
      scopes: ["bsgateway:models:read"],
      expires_at: new Date(exp * 1000).toISOString(),
      revoked_at: null,
    };
    const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
      if ((init?.method ?? "GET") !== "GET") {
        return new Response("", { status: 204 });
      }
      if (url.includes("/tenant_members")) {
        return new Response(JSON.stringify([]), { status: 200 });
      }
      return new Response(JSON.stringify([dbRow]), { status: 200 });
    }) as unknown as typeof fetch;

    const handler = createIntrospectHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
      fetchImpl,
    });
    const req = makeReq({
      method: "POST",
      headers: {
        authorization: basicHeader(validClientId, validClientSecret),
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `token=${encodeURIComponent(pat)}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = captured.body as Record<string, unknown>;
    expect(body.active).toBe(true);
    expect(body.role).toBeUndefined();
  });

  it("active=false for PAT JWT with bad signature", async () => {
    const record = await buildClientRecord();
    const exp = Math.floor(Date.now() / 1000) + 600;
    const pat = await generatePatJwt(
      {
        sub: userId,
        tenant: tenantId,
        aud: ["bsgateway"],
        scope: ["bsgateway:models:read"],
        jti: "44444444-4444-4444-4444-444444444444",
        exp,
      },
      { signingSecret: "wrong-secret-not-the-server-secret", issuer: "x" },
    );

    const fetchImpl = vi.fn() as unknown as typeof fetch;
    const handler = createIntrospectHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
      fetchImpl,
    });
    const req = makeReq({
      method: "POST",
      headers: {
        authorization: basicHeader(validClientId, validClientSecret),
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `token=${encodeURIComponent(pat)}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.body).toEqual({ active: false });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("active=false for expired PAT JWT", async () => {
    const record = await buildClientRecord();
    const exp = Math.floor(Date.now() / 1000) - 10;
    const pat = await generatePatJwt(
      {
        sub: userId,
        tenant: tenantId,
        aud: ["bsgateway"],
        scope: ["bsgateway:models:read"],
        jti: "44444444-4444-4444-4444-444444444444",
        exp,
      },
      {
        signingSecret: baseEnv.SERVICE_TOKEN_SIGNING_SECRET,
        issuer: baseEnv.SERVICE_TOKEN_ISSUER,
      },
    );

    const fetchImpl = vi.fn() as unknown as typeof fetch;
    const handler = createIntrospectHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
      fetchImpl,
    });
    const req = makeReq({
      method: "POST",
      headers: {
        authorization: basicHeader(validClientId, validClientSecret),
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `token=${encodeURIComponent(pat)}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.body).toEqual({ active: false });
  });

  it("active=false for revoked PAT JWT (no row by jti)", async () => {
    const record = await buildClientRecord();
    const exp = Math.floor(Date.now() / 1000) + 600;
    const pat = await generatePatJwt(
      {
        sub: userId,
        tenant: tenantId,
        aud: ["bsgateway"],
        scope: ["bsgateway:models:read"],
        jti: "44444444-4444-4444-4444-444444444444",
        exp,
      },
      {
        signingSecret: baseEnv.SERVICE_TOKEN_SIGNING_SECRET,
        issuer: baseEnv.SERVICE_TOKEN_ISSUER,
      },
    );

    const fetchImpl = vi.fn(async () =>
      new Response("[]", { status: 200 }),
    ) as unknown as typeof fetch;
    const handler = createIntrospectHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
      fetchImpl,
    });
    const req = makeReq({
      method: "POST",
      headers: {
        authorization: basicHeader(validClientId, validClientSecret),
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `token=${encodeURIComponent(pat)}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.body).toEqual({ active: false });
  });

});
