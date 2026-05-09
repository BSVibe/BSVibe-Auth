import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createDeviceCodeHandler } from "./code";
import { makeReq, makeRes } from "../../_lib/test-helpers";
import { type OAuthClientRecord } from "../../_lib/oauth-client";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
  AUTH_PUBLIC_BASE_URL: "https://auth.bsvibe.dev",
};

const CLIENT_ID = "device-flow-cli";

async function buildClientRecord(
  overrides: Partial<OAuthClientRecord> = {},
): Promise<OAuthClientRecord> {
  return {
    client_id: CLIENT_ID,
    client_type: "public",
    client_secret_hash: null,
    tenant_id: null,
    allowed_audiences: ["gateway"],
    allowed_scopes: ["gateway:models:read", "gateway:models:write"],
    revoked_at: null,
    ...overrides,
  };
}

interface RecordedCall {
  method?: string;
  url: string;
  body: unknown;
}

function makeFetchScript(
  responses: ((call: RecordedCall) => Response)[],
): { impl: typeof fetch; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  let i = 0;
  const impl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const call: RecordedCall = {
      method: init?.method,
      url,
      body: init?.body ? JSON.parse(init.body as string) : null,
    };
    calls.push(call);
    const responder = responses[Math.min(i, responses.length - 1)];
    i += 1;
    return responder(call);
  }) as unknown as typeof fetch;
  return { impl, calls };
}

describe("oauth/device/code", () => {
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
    const handler = createDeviceCodeHandler({ lookupClient: vi.fn() });
    const req = makeReq({ method: "OPTIONS" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(204);
  });

  it("405 on non-POST", async () => {
    const handler = createDeviceCodeHandler({ lookupClient: vi.fn() });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("400 invalid_request when client_id missing", async () => {
    const handler = createDeviceCodeHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "",
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_request" });
  });

  it("401 invalid_client when client unknown", async () => {
    const handler = createDeviceCodeHandler({
      lookupClient: vi.fn().mockResolvedValue(null),
    });
    const req = makeReq({
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `client_id=${CLIENT_ID}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
  });

  it("401 invalid_client when client revoked", async () => {
    const record = await buildClientRecord({ revoked_at: "2026-01-01T00:00:00Z" });
    const handler = createDeviceCodeHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
    });
    const req = makeReq({
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `client_id=${CLIENT_ID}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
  });

  it("400 invalid_scope when scope not allowed", async () => {
    const record = await buildClientRecord();
    const { impl } = makeFetchScript([
      () => new Response(null, { status: 201 }),
    ]);
    const handler = createDeviceCodeHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
      fetchImpl: impl,
    });
    const req = makeReq({
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `client_id=${CLIENT_ID}&scope=gateway:tenants:write`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_scope" });
  });

  it("400 invalid_target when audience not allowed", async () => {
    const record = await buildClientRecord();
    const handler = createDeviceCodeHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
    });
    const req = makeReq({
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `client_id=${CLIENT_ID}&audience=nexus`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_target" });
  });

  it("200 returns device_code + user_code (XXXX-XXXX) + verification_uri", async () => {
    const record = await buildClientRecord();
    const { impl, calls } = makeFetchScript([
      () => new Response(null, { status: 201 }),
    ]);
    const handler = createDeviceCodeHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
      fetchImpl: impl,
      now: () => Date.UTC(2026, 4, 7, 12, 0, 0),
    });
    const req = makeReq({
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `client_id=${CLIENT_ID}&scope=gateway:models:read&audience=gateway`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = captured.body as {
      device_code: string;
      user_code: string;
      verification_uri: string;
      verification_uri_complete: string;
      expires_in: number;
      interval: number;
    };
    expect(body.device_code).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(body.user_code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    expect(body.verification_uri).toBe(
      "https://auth.bsvibe.dev/oauth/device/verify",
    );
    expect(body.verification_uri_complete).toBe(
      `https://auth.bsvibe.dev/oauth/device/verify?user_code=${body.user_code}`,
    );
    expect(body.expires_in).toBe(600);
    expect(body.interval).toBe(5);

    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toContain("/rest/v1/device_codes");
    const insertBody = calls[0].body as Record<string, unknown>;
    expect(insertBody.status).toBe("pending");
    expect(insertBody.client_id).toBe(CLIENT_ID);
    expect(insertBody.scope).toEqual(["gateway:models:read"]);
    expect(insertBody.audience).toEqual(["gateway"]);
    expect(insertBody.user_id).toBeNull();
    expect(typeof insertBody.expires_at).toBe("string");
  });

  it("defaults scope to client allowed_scopes when scope not provided", async () => {
    const record = await buildClientRecord();
    const { impl, calls } = makeFetchScript([
      () => new Response(null, { status: 201 }),
    ]);
    const handler = createDeviceCodeHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
      fetchImpl: impl,
    });
    const req = makeReq({
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `client_id=${CLIENT_ID}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = (calls[0].body ?? {}) as Record<string, unknown>;
    expect(body.scope).toEqual(["gateway:models:read", "gateway:models:write"]);
  });

  it("502 when device_codes insert fails", async () => {
    const record = await buildClientRecord();
    const { impl } = makeFetchScript([
      () => new Response("upstream-down", { status: 503 }),
    ]);
    const handler = createDeviceCodeHandler({
      lookupClient: vi.fn().mockResolvedValue(record),
      fetchImpl: impl,
    });
    const req = makeReq({
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `client_id=${CLIENT_ID}`,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(502);
  });
});
