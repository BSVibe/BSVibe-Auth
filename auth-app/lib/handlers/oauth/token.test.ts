import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createOAuthTokenHandler } from "./token";
import { makeReq, makeRes } from "../_lib/test-helpers";
import {
  decodeJwtPayload,
  type ServiceTokenPayload,
} from "../_lib/service-token";
import {
  hashClientSecret,
  type OAuthClientRecord,
} from "../_lib/oauth-client";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
  SERVICE_TOKEN_SIGNING_SECRET: "test-signing-secret-32-bytes-min!!",
  SERVICE_TOKEN_ISSUER: "https://auth.bsvibe.dev",
};

const tenantId = "98aafacf-ac62-479f-b8ab-21c0fe4e113e";
const validClientId = "bsgateway-prod";
const validClientSecret = "long-random-client-secret-of-yours";

async function buildClientRecord(
  overrides: Partial<OAuthClientRecord> = {},
): Promise<OAuthClientRecord> {
  return {
    client_id: validClientId,
    client_secret_hash: await hashClientSecret(validClientSecret),
    tenant_id: tenantId,
    allowed_audiences: ["bsupervisor"],
    allowed_scopes: ["bsupervisor.write", "bsupervisor.read"],
    revoked_at: null,
    ...overrides,
  };
}

function basicHeader(id: string, secret: string): string {
  return "Basic " + Buffer.from(`${id}:${secret}`).toString("base64");
}

describe("oauth/token handler", () => {
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
    const handler = createOAuthTokenHandler({
      lookupClient: vi.fn(),
    });
    const req = makeReq({ method: "OPTIONS" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(204);
  });

  it("405 on non-POST", async () => {
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("400 invalid_request when grant_type missing", async () => {
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_request" });
  });

  it("400 unsupported_grant_type for non-client_credentials grants", async () => {
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { grant_type: "password", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "unsupported_grant_type" });
  });

  it("400 invalid_request when audience missing", async () => {
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { grant_type: "client_credentials" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_request" });
  });

  it("401 invalid_client when no credentials are provided", async () => {
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      body: { grant_type: "client_credentials", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
    expect(captured.headers["WWW-Authenticate"]).toBeDefined();
  });

  it("401 invalid_client when client does not exist", async () => {
    const lookupClient = vi.fn().mockResolvedValue(null);
    const handler = createOAuthTokenHandler({ lookupClient });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader("nope", "x") },
      body: { grant_type: "client_credentials", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
  });

  it("401 invalid_client when secret is wrong", async () => {
    const record = await buildClientRecord();
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, "wrong") },
      body: { grant_type: "client_credentials", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
  });

  it("401 invalid_client when client is revoked", async () => {
    const record = await buildClientRecord({
      revoked_at: "2026-01-01T00:00:00Z",
    });
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { grant_type: "client_credentials", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
  });

  it("400 invalid_target when audience is not in allowed_audiences", async () => {
    const record = await buildClientRecord({
      allowed_audiences: ["bsupervisor"],
    });
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { grant_type: "client_credentials", audience: "bsage" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_target" });
  });

  it("400 invalid_scope when requested scope is not allowed", async () => {
    const record = await buildClientRecord({
      allowed_scopes: ["bsupervisor.write"],
    });
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: {
        grant_type: "client_credentials",
        audience: "bsupervisor",
        scope: "bsupervisor.write bsupervisor.admin",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_scope" });
  });

  it("200 mints a service JWT with the requested scopes (client:<id> subject)", async () => {
    const record = await buildClientRecord();
    const lookupClient = vi.fn().mockResolvedValue(record);
    const touchLastUsed = vi.fn().mockResolvedValue(undefined);
    const handler = createOAuthTokenHandler({ lookupClient, touchLastUsed });

    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: {
        grant_type: "client_credentials",
        audience: "bsupervisor",
        scope: "bsupervisor.write",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as {
      access_token: string;
      expires_in: number;
      token_type: string;
      scope: string;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.scope).toBe("bsupervisor.write");

    const payload = decodeJwtPayload<ServiceTokenPayload>(body.access_token);
    expect(payload.aud).toBe("bsupervisor");
    expect(payload.sub).toBe(`client:${validClientId}`);
    expect(payload.tenant_id).toBe(tenantId);
    expect(payload.token_type).toBe("service");
    expect(payload.scope.split(" ").sort()).toEqual([
      "bsupervisor.write",
    ]);

    expect(touchLastUsed).toHaveBeenCalledWith(validClientId);
  });

  it("defaults scope to allowed_scopes when omitted", async () => {
    const record = await buildClientRecord({
      allowed_scopes: ["bsupervisor.write", "bsupervisor.read"],
    });
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });

    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { grant_type: "client_credentials", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as { scope: string; access_token: string };
    expect(body.scope.split(" ").sort()).toEqual([
      "bsupervisor.read",
      "bsupervisor.write",
    ]);
  });

  it("accepts client credentials in body (no Authorization header)", async () => {
    const record = await buildClientRecord();
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });

    const req = makeReq({
      method: "POST",
      body: {
        grant_type: "client_credentials",
        audience: "bsupervisor",
        client_id: validClientId,
        client_secret: validClientSecret,
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
  });

  it("accepts form-encoded payload (string body)", async () => {
    const record = await buildClientRecord();
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });

    const formBody = new URLSearchParams({
      grant_type: "client_credentials",
      audience: "bsupervisor",
      scope: "bsupervisor.write",
    }).toString();

    const req = makeReq({
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: basicHeader(validClientId, validClientSecret),
      },
      body: formBody,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
  });

  it("500 when SERVICE_TOKEN_SIGNING_SECRET is missing", async () => {
    delete process.env.SERVICE_TOKEN_SIGNING_SECRET;
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { grant_type: "client_credentials", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(500);
  });
});
