import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createCreateTokenHandler } from "./create";
import { makeReq, makeRes } from "../_lib/test-helpers";
import { decodePatJwtPayload, verifyPatJwtSignature } from "../_lib/api-token";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
  SERVICE_TOKEN_SIGNING_SECRET: "test-signing-secret-32-bytes-min!!",
  SERVICE_TOKEN_ISSUER: "https://auth.bsvibe.dev",
};

const USER_ID = "11111111-1111-1111-1111-111111111111";
const TENANT_ID = "22222222-2222-2222-2222-222222222222";

interface InsertCall {
  url: string;
  body: unknown;
}

function makeInsertFetch() {
  const calls: InsertCall[] = [];
  const impl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const body = init?.body ? JSON.parse(init.body as string) : null;
    calls.push({ url, body });
    return new Response("[]", {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

describe("api-tokens/create", () => {
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
    const handler = createCreateTokenHandler({
      verifyAccessToken: vi.fn(),
      getMembership: vi.fn(),
    });
    const req = makeReq({ method: "OPTIONS" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(204);
  });

  it("405 on non-POST", async () => {
    const handler = createCreateTokenHandler({
      verifyAccessToken: vi.fn(),
      getMembership: vi.fn(),
    });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("401 when Authorization header missing", async () => {
    const handler = createCreateTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      getMembership: vi.fn(),
    });
    const req = makeReq({ method: "POST", body: {} });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("401 when access_token invalid", async () => {
    const handler = createCreateTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(null),
      getMembership: vi.fn(),
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer bad" },
      body: {},
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("400 when type is invalid", async () => {
    const handler = createCreateTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      getMembership: vi.fn(),
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer ok" },
      body: { type: "wrong", name: "n", tenant_id: TENANT_ID, scopes: [], audience: [] },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("400 when name missing", async () => {
    const handler = createCreateTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      getMembership: vi.fn(),
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer ok" },
      body: { type: "api_key", tenant_id: TENANT_ID, scopes: [], audience: [] },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("403 when user is not a member of the tenant", async () => {
    const handler = createCreateTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      getMembership: vi.fn().mockResolvedValue(null),
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer ok" },
      body: {
        type: "api_key",
        name: "key",
        tenant_id: TENANT_ID,
        scopes: ["gateway:models:read"],
        audience: ["gateway"],
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
  });

  it("201 mints opaque api_key, returns raw token once + metadata", async () => {
    const { impl, calls } = makeInsertFetch();
    const handler = createCreateTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      getMembership: vi.fn().mockResolvedValue("admin"),
      fetchImpl: impl,
      emitAudit: vi.fn().mockResolvedValue({ ok: true, eventId: "x" }),
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer ok" },
      body: {
        type: "api_key",
        name: "ci-key",
        tenant_id: TENANT_ID,
        scopes: ["gateway:models:read"],
        audience: ["gateway"],
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(201);
    const body = captured.body as {
      id: string;
      type: string;
      name: string;
      prefix: string;
      token: string;
      scopes: string[];
      audience: string[];
    };
    expect(body.type).toBe("api_key");
    expect(body.name).toBe("ci-key");
    expect(body.token.startsWith("bsv_sk_")).toBe(true);
    expect(body.prefix).toBe(body.token.slice(0, 12));
    expect(body.scopes).toEqual(["gateway:models:read"]);
    expect(body.audience).toEqual(["gateway"]);
    // No raw secret stored — token_hash is sent as \\x... hex
    const tokenInsert = calls.find((c) => c.url.endsWith("/rest/v1/tokens"));
    expect(tokenInsert).toBeDefined();
    const inserted = tokenInsert!.body as Record<string, unknown>;
    expect(inserted.type).toBe("api_key");
    expect(inserted.user_id).toBe(USER_ID);
    expect(inserted.tenant_id).toBe(TENANT_ID);
    expect(typeof inserted.token_hash).toBe("string");
    expect(String(inserted.token_hash).startsWith("\\x")).toBe(true);
  });

  it("201 mints PAT JWT + refresh_token; jti tracked in tokens row", async () => {
    const { impl, calls } = makeInsertFetch();
    const emit = vi.fn().mockResolvedValue({ ok: true, eventId: "x" });
    const handler = createCreateTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      getMembership: vi.fn().mockResolvedValue("owner"),
      fetchImpl: impl,
      emitAudit: emit,
      now: () => 1700000000000,
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer ok" },
      body: {
        type: "pat",
        name: "cli-pat",
        tenant_id: TENANT_ID,
        scopes: ["gateway:models:read"],
        audience: ["gateway"],
        expires_in_s: 7200,
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(201);
    const body = captured.body as {
      id: string;
      type: string;
      access_token: string;
      refresh_token: string;
      token_type: string;
      expires_in: number;
      audience: string[];
    };
    expect(body.type).toBe("pat");
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(7200);
    expect(body.refresh_token.length).toBeGreaterThan(20);
    // PAT JWT verifies + carries the right claims
    const valid = await verifyPatJwtSignature(
      body.access_token,
      baseEnv.SERVICE_TOKEN_SIGNING_SECRET,
    );
    expect(valid).toBe(true);
    const payload = decodePatJwtPayload(body.access_token);
    expect(payload.sub).toBe(USER_ID);
    expect(payload.tenant).toBe(TENANT_ID);
    expect(payload.aud).toEqual(["gateway"]);
    expect(payload.scope).toEqual(["gateway:models:read"]);
    expect(payload.token_type).toBe("pat");
    // Tokens row inserted with same jti
    const tokenInsert = calls.find((c) => c.url.endsWith("/rest/v1/tokens"));
    const inserted = tokenInsert!.body as Record<string, unknown>;
    expect(inserted.jti).toBe(payload.jti);
    expect(inserted.type).toBe("pat");
    // refresh_tokens row inserted referencing token_id
    const refreshInsert = calls.find((c) =>
      c.url.endsWith("/rest/v1/refresh_tokens"),
    );
    expect(refreshInsert).toBeDefined();
    const refreshRow = refreshInsert!.body as Record<string, unknown>;
    expect(refreshRow.token_id).toBe(inserted.id);
    // audit event emitted
    expect(emit).toHaveBeenCalled();
    const emittedInput = emit.mock.calls[0][1] as {
      eventType: string;
      data: Record<string, unknown>;
    };
    expect(emittedInput.eventType).toBe("token.created");
    expect(emittedInput.data.token_id).toBe(inserted.id);
    // Raw token never logged in audit data
    expect(JSON.stringify(emittedInput.data)).not.toContain(body.access_token);
    expect(JSON.stringify(emittedInput.data)).not.toContain(body.refresh_token);
  });

  it("502 when token row insert fails", async () => {
    const impl = vi.fn(async () =>
      new Response("err", { status: 500 }),
    ) as unknown as typeof fetch;
    const handler = createCreateTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      getMembership: vi.fn().mockResolvedValue("admin"),
      fetchImpl: impl,
      emitAudit: vi.fn(),
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer ok" },
      body: {
        type: "api_key",
        name: "k",
        tenant_id: TENANT_ID,
        scopes: [],
        audience: ["gateway"],
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(502);
  });
});
