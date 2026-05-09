import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { claimDeviceCode } from "./token";

const env = {
  url: "https://test.supabase.co",
  serviceRoleKey: "service-role-key",
};

const DEVICE_CODE = "abc.device.code";
const CLIENT_ID = "device-flow-cli";
const USER_ID = "11111111-1111-1111-1111-111111111111";
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

describe("oauth/device/token claimDeviceCode", () => {
  beforeEach(() => {});
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns claimed on approved row + filters by client_id + status='approved' + non-expired", async () => {
    const { impl, calls } = makeFetchScript([
      () =>
        new Response(
          JSON.stringify([
            {
              device_code: DEVICE_CODE,
              client_id: CLIENT_ID,
              user_id: USER_ID,
              tenant_id: TENANT_ID,
              scope: ["gateway:models:read"],
              audience: ["gateway"],
              status: "consumed",
            },
          ]),
          { status: 200 },
        ),
    ]);
    const result = await claimDeviceCode(env, DEVICE_CODE, CLIENT_ID, {
      fetchImpl: impl,
      now: () => Date.UTC(2026, 4, 7, 12, 0, 0),
    });
    expect(result.kind).toBe("claimed");
    if (result.kind === "claimed") {
      expect(result.userId).toBe(USER_ID);
      expect(result.tenantId).toBe(TENANT_ID);
      expect(result.scope).toEqual(["gateway:models:read"]);
      expect(result.audience).toEqual(["gateway"]);
    }
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("PATCH");
    expect(calls[0].url).toContain(`device_code=eq.${DEVICE_CODE}`);
    expect(calls[0].url).toContain(`client_id=eq.${CLIENT_ID}`);
    expect(calls[0].url).toContain("status=eq.approved");
    expect(calls[0].url).toContain("expires_at=gt.");
    const body = calls[0].body as Record<string, unknown>;
    expect(body.status).toBe("consumed");
  });

  it("returns 'pending' when claim returns no rows and current row is pending", async () => {
    const { impl } = makeFetchScript([
      // PATCH returns []
      () => new Response(JSON.stringify([]), { status: 200 }),
      // GET returns pending
      () =>
        new Response(
          JSON.stringify([
            {
              device_code: DEVICE_CODE,
              client_id: CLIENT_ID,
              user_id: null,
              scope: [],
              audience: [],
              status: "pending",
              expires_at: new Date(
                Date.UTC(2026, 4, 7, 12, 5, 0),
              ).toISOString(),
            },
          ]),
          { status: 200 },
        ),
    ]);
    const result = await claimDeviceCode(env, DEVICE_CODE, CLIENT_ID, {
      fetchImpl: impl,
      now: () => Date.UTC(2026, 4, 7, 12, 0, 0),
    });
    expect(result.kind).toBe("pending");
  });

  it("returns 'denied' when row was denied", async () => {
    const { impl } = makeFetchScript([
      () => new Response(JSON.stringify([]), { status: 200 }),
      () =>
        new Response(
          JSON.stringify([
            {
              device_code: DEVICE_CODE,
              client_id: CLIENT_ID,
              user_id: USER_ID,
              scope: [],
              audience: [],
              status: "denied",
              expires_at: new Date(
                Date.UTC(2026, 4, 7, 12, 5, 0),
              ).toISOString(),
            },
          ]),
          { status: 200 },
        ),
    ]);
    const result = await claimDeviceCode(env, DEVICE_CODE, CLIENT_ID, {
      fetchImpl: impl,
      now: () => Date.UTC(2026, 4, 7, 12, 0, 0),
    });
    expect(result.kind).toBe("denied");
  });

  it("returns 'expired' when row past expires_at", async () => {
    const { impl } = makeFetchScript([
      () => new Response(JSON.stringify([]), { status: 200 }),
      () =>
        new Response(
          JSON.stringify([
            {
              device_code: DEVICE_CODE,
              client_id: CLIENT_ID,
              user_id: null,
              scope: [],
              audience: [],
              status: "approved",
              expires_at: new Date(
                Date.UTC(2026, 4, 7, 11, 0, 0),
              ).toISOString(),
            },
          ]),
          { status: 200 },
        ),
    ]);
    const result = await claimDeviceCode(env, DEVICE_CODE, CLIENT_ID, {
      fetchImpl: impl,
      now: () => Date.UTC(2026, 4, 7, 12, 0, 0),
    });
    expect(result.kind).toBe("expired");
  });

  it("returns 'consumed' on replay (already-consumed row)", async () => {
    const { impl } = makeFetchScript([
      () => new Response(JSON.stringify([]), { status: 200 }),
      () =>
        new Response(
          JSON.stringify([
            {
              device_code: DEVICE_CODE,
              client_id: CLIENT_ID,
              user_id: USER_ID,
              scope: [],
              audience: [],
              status: "consumed",
              expires_at: new Date(
                Date.UTC(2026, 4, 7, 12, 5, 0),
              ).toISOString(),
            },
          ]),
          { status: 200 },
        ),
    ]);
    const result = await claimDeviceCode(env, DEVICE_CODE, CLIENT_ID, {
      fetchImpl: impl,
      now: () => Date.UTC(2026, 4, 7, 12, 0, 0),
    });
    expect(result.kind).toBe("consumed");
  });

  it("returns 'not_found' on unknown device_code", async () => {
    const { impl } = makeFetchScript([
      () => new Response(JSON.stringify([]), { status: 200 }),
      () => new Response(JSON.stringify([]), { status: 200 }),
    ]);
    const result = await claimDeviceCode(env, "nope", CLIENT_ID, {
      fetchImpl: impl,
      now: () => Date.UTC(2026, 4, 7, 12, 0, 0),
    });
    expect(result.kind).toBe("not_found");
  });

  it("returns 'not_found' when client_id mismatches the row owner", async () => {
    const { impl } = makeFetchScript([
      () => new Response(JSON.stringify([]), { status: 200 }),
      // Row exists but is owned by a different client; lookup is also scoped
      // to client_id, so it returns [].
      () => new Response(JSON.stringify([]), { status: 200 }),
    ]);
    const result = await claimDeviceCode(env, DEVICE_CODE, "other-cli", {
      fetchImpl: impl,
      now: () => Date.UTC(2026, 4, 7, 12, 0, 0),
    });
    expect(result.kind).toBe("not_found");
  });
});
