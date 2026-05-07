import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createDeviceLookupHandler } from "./lookup";
import { makeReq, makeRes } from "../../_lib/test-helpers";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
};

const USER_ID = "11111111-1111-1111-1111-111111111111";
const USER_CODE = "ABCD-2345";

describe("oauth/device/lookup", () => {
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
    const handler = createDeviceLookupHandler({
      verifyAccessToken: vi.fn(),
    });
    const req = makeReq({ method: "POST" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("401 when not authenticated", async () => {
    const handler = createDeviceLookupHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(null),
    });
    const req = makeReq({
      method: "GET",
      headers: { authorization: "Bearer x" },
      query: { user_code: USER_CODE },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("400 when user_code missing or malformed", async () => {
    const handler = createDeviceLookupHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
    });
    const req = makeReq({
      method: "GET",
      headers: { authorization: "Bearer u" },
      query: { user_code: "not-a-code" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("404 when no pending row matches", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify([]), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ) as unknown as typeof fetch;
    const handler = createDeviceLookupHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl,
    });
    const req = makeReq({
      method: "GET",
      headers: { authorization: "Bearer u" },
      query: { user_code: USER_CODE },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(404);
  });

  it("returns scope + audience + client_id + expires_at on hit", async () => {
    const fetchCalls: string[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      fetchCalls.push(typeof input === "string" ? input : input.toString());
      return new Response(
        JSON.stringify([
          {
            user_code: USER_CODE,
            client_id: "device-client",
            scope: ["gateway:models:read", "gateway:routing:read"],
            audience: ["gateway"],
            expires_at: "2099-01-01T00:00:00Z",
            status: "pending",
          },
        ]),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof fetch;
    const handler = createDeviceLookupHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl,
    });
    const req = makeReq({
      method: "GET",
      headers: { authorization: "Bearer u" },
      query: { user_code: USER_CODE },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = captured.body as {
      user_code: string;
      client_id: string;
      scope: string[];
      audience: string[];
      expires_at: string;
    };
    expect(body.user_code).toBe(USER_CODE);
    expect(body.client_id).toBe("device-client");
    expect(body.scope).toEqual([
      "gateway:models:read",
      "gateway:routing:read",
    ]);
    expect(body.audience).toEqual(["gateway"]);
    // Should filter on status=pending (not consumed/expired/etc.).
    expect(fetchCalls[0]).toMatch(/status=eq\.pending/);
    expect(fetchCalls[0]).toMatch(/expires_at=gt\./);
  });

  it("uppercases lowercase user_code before matching", async () => {
    const fetchCalls: string[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      fetchCalls.push(typeof input === "string" ? input : input.toString());
      return new Response(
        JSON.stringify([
          {
            user_code: USER_CODE,
            client_id: "device-client",
            scope: [],
            audience: [],
            expires_at: "2099-01-01T00:00:00Z",
            status: "pending",
          },
        ]),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }) as unknown as typeof fetch;
    const handler = createDeviceLookupHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl,
    });
    const req = makeReq({
      method: "GET",
      headers: { authorization: "Bearer u" },
      query: { user_code: USER_CODE.toLowerCase() },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect(fetchCalls[0]).toMatch(`user_code=eq.${USER_CODE}`);
  });
});
