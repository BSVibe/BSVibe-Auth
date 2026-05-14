import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createListTokensHandler } from "./list";
import { makeReq, makeRes } from "../_lib/test-helpers";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
};

const USER_ID = "11111111-1111-1111-1111-111111111111";

interface FetchSpy {
  calls: string[];
  impl: typeof fetch;
}

function makeFetchRows(rows: unknown[]): FetchSpy {
  const calls: string[] = [];
  const impl = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push(url);
    return new Response(JSON.stringify(rows), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { calls, impl };
}

describe("api-tokens/list", () => {
  let envBackup: NodeJS.ProcessEnv;

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });

  afterEach(() => {
    process.env = envBackup;
    vi.restoreAllMocks();
  });

  it("405 on non-GET", async () => {
    const handler = createListTokensHandler({
      verifyAccessToken: vi.fn(),
    });
    const req = makeReq({ method: "POST" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("401 when not authenticated", async () => {
    const handler = createListTokensHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(null),
      fetchImpl: makeFetchRows([]).impl,
    });
    const req = makeReq({ method: "GET", headers: { authorization: "Bearer x" } });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("200 returns metadata only — no raw tokens or hashes", async () => {
    const rows = [
      {
        id: "t1",
        type: "api_key",
        prefix: "bsv_sk_abc",
        name: "ci-key",
        audience: ["bsgateway"],
        scopes: ["bsgateway:models:read"],
        created_at: "2026-05-01T00:00:00Z",
        expires_at: null,
        last_used_at: null,
        revoked_at: null,
      },
    ];
    const { impl, calls } = makeFetchRows(rows);
    const handler = createListTokensHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: impl,
    });
    const req = makeReq({
      method: "GET",
      headers: { authorization: "Bearer ok" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = captured.body as { tokens: unknown[] };
    expect(body.tokens).toHaveLength(1);
    const serialized = JSON.stringify(captured.body);
    expect(serialized).not.toContain("token_hash");
    expect(serialized).not.toContain("jti");
    // user filter applied at REST layer
    expect(calls[0]).toContain(`user_id=eq.${USER_ID}`);
    // only metadata columns selected
    expect(calls[0]).toContain("select=");
    expect(calls[0]).not.toContain("token_hash");
  });

  it("filters by ?type=pat", async () => {
    const { impl, calls } = makeFetchRows([]);
    const handler = createListTokensHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: impl,
    });
    const req = makeReq({
      method: "GET",
      query: { type: "pat" },
      headers: { authorization: "Bearer ok" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect(calls[0]).toContain("type=eq.pat");
  });

  it("400 when type filter is invalid", async () => {
    const handler = createListTokensHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: makeFetchRows([]).impl,
    });
    const req = makeReq({
      method: "GET",
      query: { type: "invalid" },
      headers: { authorization: "Bearer ok" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });
});
