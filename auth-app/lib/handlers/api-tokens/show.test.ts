import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createShowTokenHandler } from "./show";
import { makeReq, makeRes } from "../_lib/test-helpers";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
};

const USER_ID = "11111111-1111-1111-1111-111111111111";

function makeFetchRows(rows: unknown[]) {
  return vi.fn(async () =>
    new Response(JSON.stringify(rows), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  ) as unknown as typeof fetch;
}

describe("api-tokens/show", () => {
  let envBackup: NodeJS.ProcessEnv;

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });

  afterEach(() => {
    process.env = envBackup;
    vi.restoreAllMocks();
  });

  it("401 when not authenticated", async () => {
    const handler = createShowTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(null),
      fetchImpl: makeFetchRows([]),
    });
    const req = makeReq({
      method: "GET",
      query: { id: "33333333-3333-3333-3333-333333333333" },
      headers: { authorization: "Bearer x" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("400 when id missing or invalid", async () => {
    const handler = createShowTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: makeFetchRows([]),
    });
    const req = makeReq({
      method: "GET",
      query: {},
      headers: { authorization: "Bearer ok" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("404 when token not found / not user's", async () => {
    const handler = createShowTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: makeFetchRows([]),
    });
    const req = makeReq({
      method: "GET",
      query: { id: "33333333-3333-3333-3333-333333333333" },
      headers: { authorization: "Bearer ok" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(404);
  });

  it("200 reads id from url path when query.id is absent (Next.js dynamic route)", async () => {
    const tokenId = "33333333-3333-3333-3333-333333333333";
    const row = {
      id: tokenId,
      type: "api_key",
      prefix: "bsv_sk_abc",
      name: "k",
      audience: ["gateway"],
      scopes: ["gateway:models:read"],
      created_at: "2026-05-01T00:00:00Z",
      expires_at: null,
      last_used_at: null,
      revoked_at: null,
    };
    const handler = createShowTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: makeFetchRows([row]),
    });
    const req = makeReq({
      method: "GET",
      query: {},
      url: `https://auth.bsvibe.dev/api/tokens/${tokenId}`,
      headers: { authorization: "Bearer ok" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = captured.body as { token: { id: string } };
    expect(body.token.id).toBe(tokenId);
  });

  it("200 returns metadata only", async () => {
    const row = {
      id: "33333333-3333-3333-3333-333333333333",
      type: "api_key",
      prefix: "bsv_sk_abc",
      name: "k",
      audience: ["gateway"],
      scopes: ["gateway:models:read"],
      created_at: "2026-05-01T00:00:00Z",
      expires_at: null,
      last_used_at: null,
      revoked_at: null,
    };
    const handler = createShowTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: makeFetchRows([row]),
    });
    const req = makeReq({
      method: "GET",
      query: { id: "33333333-3333-3333-3333-333333333333" },
      headers: { authorization: "Bearer ok" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = captured.body as { token: Record<string, unknown> };
    expect(body.token.id).toBe(row.id);
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain("token_hash");
  });
});
