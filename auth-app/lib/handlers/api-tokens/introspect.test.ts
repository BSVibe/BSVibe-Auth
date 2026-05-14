import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createIntrospectHandler } from "./introspect";
import { makeReq, makeRes } from "../_lib/test-helpers";
import {
  hashClientSecret,
  type OAuthClientRecord,
} from "../_lib/oauth-client";
import {
  generateOpaqueToken,
  generatePatJwt,
  bytesToHex,
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

  it("active=true for valid opaque api_key", async () => {
    const record = await buildClientRecord();
    const opaque = await generateOpaqueToken("bsv_sk_");
    const tokenId = "33333333-3333-3333-3333-333333333333";
    const expIso = new Date(Date.now() + 60_000).toISOString();
    const dbRow = {
      id: tokenId,
      user_id: userId,
      tenant_id: tenantId,
      type: "api_key",
      audience: ["bsgateway"],
      scopes: ["bsgateway:models:read", "bsgateway:models:write"],
      expires_at: expIso,
      revoked_at: null,
    };

    const fetchCalls: { url: string; init?: RequestInit }[] = [];
    const fetchImpl = vi.fn(async (url: string, init?: RequestInit) => {
      fetchCalls.push({ url, init });
      const u = new URL(url);
      if (u.pathname.endsWith("/rest/v1/tokens") && (init?.method ?? "GET") === "GET") {
        return new Response(JSON.stringify([dbRow]), { status: 200 });
      }
      // last_used_at PATCH
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
      body: `token=${encodeURIComponent(opaque.raw)}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as Record<string, unknown>;
    expect(body.active).toBe(true);
    expect(body.sub).toBe(userId);
    expect(body.tenant).toBe(tenantId);
    expect(body.aud).toEqual(["bsgateway"]);
    expect(body.scope).toBe("bsgateway:models:read bsgateway:models:write");
    expect(body.client_id).toBe(validClientId);
    expect(body.token_type).toBe("api_key");
    // confirm body.exp present and an integer epoch second
    expect(typeof body.exp).toBe("number");

    // confirm lookup URL referenced prefix and token_hash filters
    const lookupCall = fetchCalls.find((c) =>
      c.url.includes("/rest/v1/tokens?"),
    );
    expect(lookupCall).toBeDefined();
    const lookupU = new URL(lookupCall!.url);
    expect(lookupU.searchParams.get("prefix")).toBe(`eq.${opaque.prefix}`);
    expect(lookupU.searchParams.get("token_hash")).toBe(
      `eq.\\x${bytesToHex(opaque.hash)}`,
    );
    expect(lookupU.searchParams.get("revoked_at")).toBe("is.null");

    // best-effort last_used_at update issued (same path, PATCH method)
    const patchCall = fetchCalls.find((c) => (c.init?.method ?? "") === "PATCH");
    expect(patchCall).toBeDefined();
  });

  it("active=false when opaque token row not found", async () => {
    const record = await buildClientRecord();
    const opaque = await generateOpaqueToken("bsv_pk_");
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
      body: `token=${encodeURIComponent(opaque.raw)}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect(captured.body).toEqual({ active: false });
  });

  it("active=false when opaque token revoked (filter excludes it)", async () => {
    // The revoked_at=is.null filter at the DB layer; if revoked, no row returned
    const record = await buildClientRecord();
    const opaque = await generateOpaqueToken("bsv_sk_");
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
      body: `token=${encodeURIComponent(opaque.raw)}`,
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

  it("response never includes raw token or hash bytes", async () => {
    const record = await buildClientRecord();
    const opaque = await generateOpaqueToken("bsv_sk_");
    const dbRow = {
      id: "33333333-3333-3333-3333-333333333333",
      user_id: userId,
      tenant_id: tenantId,
      type: "api_key",
      audience: ["bsgateway"],
      scopes: ["bsgateway:models:read"],
      expires_at: null,
      revoked_at: null,
      token_hash: "should-never-leak",
    };
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify([dbRow]), { status: 200 }),
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
      body: `token=${encodeURIComponent(opaque.raw)}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    const serialized = JSON.stringify(captured.body);
    expect(serialized).not.toContain("token_hash");
    expect(serialized).not.toContain(opaque.raw);
  });
});
