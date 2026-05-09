import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createDeviceVerifyHandler } from "./verify";
import { makeReq, makeRes } from "../../_lib/test-helpers";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
};

const USER_ID = "11111111-1111-1111-1111-111111111111";
const USER_CODE = "ABCD-2345";
const TENANT_ID = "22222222-2222-2222-2222-222222222222";

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

describe("oauth/device/verify", () => {
  let envBackup: NodeJS.ProcessEnv;

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });

  afterEach(() => {
    process.env = envBackup;
    vi.restoreAllMocks();
  });

  it("405 on non-POST", async () => {
    const handler = createDeviceVerifyHandler({
      verifyAccessToken: vi.fn(),
    });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("401 when not authenticated", async () => {
    const handler = createDeviceVerifyHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(null),
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer x" },
      body: { user_code: USER_CODE, action: "approve" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("400 when user_code missing", async () => {
    const handler = createDeviceVerifyHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer u" },
      body: { action: "approve" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("400 when action invalid", async () => {
    const handler = createDeviceVerifyHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer u" },
      body: { user_code: USER_CODE, action: "maybe" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("404 when user_code not found / not pending", async () => {
    const { impl } = makeFetchScript([
      () => new Response(JSON.stringify([]), { status: 200 }),
    ]);
    const handler = createDeviceVerifyHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: impl,
      resolvePrimaryTenantId: vi.fn().mockResolvedValue(TENANT_ID),
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer u" },
      body: { user_code: USER_CODE, action: "approve" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(404);
  });

  it("approve sets status='approved' + records user_id + stamps tenant_id from primary tenant", async () => {
    const { impl, calls } = makeFetchScript([
      () =>
        new Response(
          JSON.stringify([
            {
              device_code: "dev-1",
              client_id: "cli",
              status: "approved",
              user_id: USER_ID,
              tenant_id: TENANT_ID,
            },
          ]),
          { status: 200 },
        ),
    ]);
    const handler = createDeviceVerifyHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: impl,
      resolvePrimaryTenantId: vi.fn().mockResolvedValue(TENANT_ID),
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer u" },
      body: { user_code: USER_CODE, action: "approve" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect(captured.body).toMatchObject({ status: "approved" });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("PATCH");
    const patchBody = calls[0].body as Record<string, unknown>;
    expect(patchBody.status).toBe("approved");
    expect(patchBody.user_id).toBe(USER_ID);
    expect(patchBody.tenant_id).toBe(TENANT_ID);
    expect(calls[0].url).toContain(
      `user_code=eq.${encodeURIComponent(USER_CODE)}`,
    );
    expect(calls[0].url).toContain("status=eq.pending");
  });

  it("approve fails 403 when user has no tenant membership", async () => {
    const { impl, calls } = makeFetchScript([
      () => new Response(JSON.stringify([]), { status: 200 }),
    ]);
    const handler = createDeviceVerifyHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: impl,
      resolvePrimaryTenantId: vi.fn().mockResolvedValue(null),
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer u" },
      body: { user_code: USER_CODE, action: "approve" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
    expect(captured.body).toMatchObject({ error: "no_tenant_membership" });
    // The PATCH must NOT have fired — no tenant means no approval.
    expect(calls).toHaveLength(0);
  });

  it("deny sets status='denied'", async () => {
    const { impl, calls } = makeFetchScript([
      () =>
        new Response(
          JSON.stringify([
            { device_code: "dev-2", client_id: "cli", status: "denied" },
          ]),
          { status: 200 },
        ),
    ]);
    const handler = createDeviceVerifyHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: impl,
    });
    const req = makeReq({
      method: "POST",
      headers: { authorization: "Bearer u" },
      body: { user_code: USER_CODE, action: "deny" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect(captured.body).toMatchObject({ status: "denied" });
    const patchBody = calls[0].body as Record<string, unknown>;
    expect(patchBody.status).toBe("denied");
  });
});
