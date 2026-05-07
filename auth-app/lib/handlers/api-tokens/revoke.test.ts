import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createRevokeTokenHandler } from "./revoke";
import { makeReq, makeRes } from "../_lib/test-helpers";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
};

const USER_ID = "11111111-1111-1111-1111-111111111111";
const TOKEN_ID = "33333333-3333-3333-3333-333333333333";
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

describe("api-tokens/revoke", () => {
  let envBackup: NodeJS.ProcessEnv;

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });

  afterEach(() => {
    process.env = envBackup;
    vi.restoreAllMocks();
  });

  it("405 on non-DELETE", async () => {
    const handler = createRevokeTokenHandler({
      verifyAccessToken: vi.fn(),
    });
    const req = makeReq({ method: "GET", query: { id: TOKEN_ID } });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("401 when not authenticated", async () => {
    const handler = createRevokeTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(null),
    });
    const req = makeReq({
      method: "DELETE",
      query: { id: TOKEN_ID },
      headers: { authorization: "Bearer x" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("404 when token not found / not user's", async () => {
    // GET returns []
    const { impl } = makeFetchScript([
      () =>
        new Response("[]", {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    ]);
    const handler = createRevokeTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: impl,
      emitAudit: vi.fn(),
    });
    const req = makeReq({
      method: "DELETE",
      query: { id: TOKEN_ID },
      headers: { authorization: "Bearer ok" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(404);
  });

  it("200 sets revoked_at and emits token.revoked", async () => {
    const existingRow = [
      {
        id: TOKEN_ID,
        user_id: USER_ID,
        tenant_id: TENANT_ID,
        type: "api_key",
        revoked_at: null,
      },
    ];
    const { impl, calls } = makeFetchScript([
      // 1) lookup
      () =>
        new Response(JSON.stringify(existingRow), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      // 2) PATCH
      () =>
        new Response(JSON.stringify([{ ...existingRow[0], revoked_at: "now" }]), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    ]);
    const emit = vi.fn().mockResolvedValue({ ok: true, eventId: "x" });
    const handler = createRevokeTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: impl,
      emitAudit: emit,
    });
    const req = makeReq({
      method: "DELETE",
      query: { id: TOKEN_ID },
      headers: { authorization: "Bearer ok" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const patch = calls[1];
    expect(patch.method).toBe("PATCH");
    const patchBody = patch.body as Record<string, unknown>;
    expect(typeof patchBody.revoked_at).toBe("string");
    // user_id filter prevents cross-user revoke
    expect(patch.url).toContain(`user_id=eq.${USER_ID}`);
    expect(patch.url).toContain(`id=eq.${TOKEN_ID}`);
    // audit fires; raw token never logged
    expect(emit).toHaveBeenCalled();
    const audit = emit.mock.calls[0][1] as { eventType: string; data: Record<string, unknown> };
    expect(audit.eventType).toBe("token.revoked");
    expect(audit.data.token_id).toBe(TOKEN_ID);
  });

  it("idempotent: 200 when already revoked", async () => {
    const revokedRow = [
      {
        id: TOKEN_ID,
        user_id: USER_ID,
        tenant_id: TENANT_ID,
        type: "api_key",
        revoked_at: "2026-05-01T00:00:00Z",
      },
    ];
    const { impl } = makeFetchScript([
      () =>
        new Response(JSON.stringify(revokedRow), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    ]);
    const handler = createRevokeTokenHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(USER_ID),
      fetchImpl: impl,
      emitAudit: vi.fn(),
    });
    const req = makeReq({
      method: "DELETE",
      query: { id: TOKEN_ID },
      headers: { authorization: "Bearer ok" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = captured.body as { already_revoked: boolean };
    expect(body.already_revoked).toBe(true);
  });
});
