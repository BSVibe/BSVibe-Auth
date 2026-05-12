import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { createRevokeOAuthClientHandler } from "./revoke";
import { makeReq, makeRes } from "../_lib/test-helpers";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
};

const userId = "00000000-0000-0000-0000-000000000001";
const tenantId = "10000000-0000-0000-0000-000000000010";
const clientId = "svc-deadbeefdeadbeef";

function makeFetch(
  responses: Array<{ ok: boolean; json?: () => Promise<unknown>; status?: number }>,
) {
  let i = 0;
  return vi.fn().mockImplementation(async () => {
    const r = responses[i++];
    if (!r) throw new Error("unexpected fetch call");
    return {
      ok: r.ok,
      status: r.status ?? (r.ok ? 200 : 500),
      json: r.json ?? (async () => null),
    };
  }) as unknown as typeof fetch;
}

function authedReq() {
  return makeReq({
    method: "DELETE",
    headers: { authorization: "Bearer user" },
    url: `/api/oauth/clients/${clientId}`,
  });
}

describe("oauth-clients/revoke handler", () => {
  let envBackup: NodeJS.ProcessEnv;
  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });
  afterEach(() => {
    process.env = envBackup;
    vi.restoreAllMocks();
  });

  it("400 on malformed client_id", async () => {
    const handler = createRevokeOAuthClientHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(userId),
      resolveTenantId: vi.fn().mockResolvedValue(tenantId),
    });
    const req = makeReq({
      method: "DELETE",
      headers: { authorization: "Bearer x" },
      url: "/api/oauth/clients/not-a-real-id",
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("404 when client absent in caller's tenant", async () => {
    const fetchImpl = makeFetch([{ ok: true, json: async () => [] }]);
    const handler = createRevokeOAuthClientHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(userId),
      resolveTenantId: vi.fn().mockResolvedValue(tenantId),
      fetchImpl,
    });
    const { res, captured } = makeRes();
    await handler(authedReq(), res);
    expect(captured.statusCode).toBe(404);
  });

  it("200 already_revoked when revoked_at is set", async () => {
    const fetchImpl = makeFetch([
      {
        ok: true,
        json: async () => [
          {
            client_id: clientId,
            tenant_id: tenantId,
            client_type: "confidential",
            revoked_at: "2026-05-12T00:00:00Z",
          },
        ],
      },
    ]);
    const handler = createRevokeOAuthClientHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(userId),
      resolveTenantId: vi.fn().mockResolvedValue(tenantId),
      fetchImpl,
    });
    const { res, captured } = makeRes();
    await handler(authedReq(), res);
    expect(captured.statusCode).toBe(200);
    expect((captured.body as { already_revoked: boolean }).already_revoked).toBe(
      true,
    );
  });

  it("200 revoked + audit emitted on happy path", async () => {
    const fetchImpl = makeFetch([
      {
        ok: true,
        json: async () => [
          {
            client_id: clientId,
            tenant_id: tenantId,
            client_type: "confidential",
            revoked_at: null,
          },
        ],
      },
      { ok: true },
    ]);
    const audits: unknown[] = [];
    const handler = createRevokeOAuthClientHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(userId),
      resolveTenantId: vi.fn().mockResolvedValue(tenantId),
      fetchImpl,
      emitAudit: async (i) => {
        audits.push(i);
      },
    });
    const { res, captured } = makeRes();
    await handler(authedReq(), res);
    expect(captured.statusCode).toBe(200);
    expect((captured.body as { revoked: boolean }).revoked).toBe(true);
    expect(audits.length).toBe(1);
    // Second fetch was a PATCH scoped by tenant_id to block cross-tenant revoke.
    const patchUrl = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[1][0] as string;
    expect(patchUrl).toContain(`tenant_id=eq.${tenantId}`);
    expect(patchUrl).toContain(`client_id=eq.${clientId}`);
  });
});
