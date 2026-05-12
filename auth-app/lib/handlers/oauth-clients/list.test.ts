import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { createListOAuthClientsHandler } from "./list";
import { makeReq, makeRes } from "../_lib/test-helpers";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
};

const userId = "00000000-0000-0000-0000-000000000001";
const tenantId = "10000000-0000-0000-0000-000000000010";

describe("oauth-clients/list handler", () => {
  let envBackup: NodeJS.ProcessEnv;
  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });
  afterEach(() => {
    process.env = envBackup;
    vi.restoreAllMocks();
  });

  it("401 when no auth header", async () => {
    const handler = createListOAuthClientsHandler({
      verifyAccessToken: vi.fn(),
    });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("empty clients when no tenant membership", async () => {
    const handler = createListOAuthClientsHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(userId),
      resolveTenantId: vi.fn().mockResolvedValue(null),
    });
    const req = makeReq({
      method: "GET",
      headers: { authorization: "Bearer x" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect((captured.body as { clients: unknown[] }).clients).toEqual([]);
  });

  it("returns metadata-only rows scoped to caller's tenant", async () => {
    const rows = [
      {
        client_id: "svc-deadbeefdeadbeef",
        description: "ci",
        tenant_id: tenantId,
        client_type: "confidential",
        allowed_audiences: ["gateway"],
        allowed_scopes: ["gateway:read"],
        created_at: "2026-05-12T00:00:00Z",
        revoked_at: null,
        last_used_at: null,
      },
    ];
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => rows,
    }) as unknown as typeof fetch;
    const handler = createListOAuthClientsHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(userId),
      resolveTenantId: vi.fn().mockResolvedValue(tenantId),
      fetchImpl,
    });
    const req = makeReq({
      method: "GET",
      headers: { authorization: "Bearer x" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    expect((captured.body as { clients: unknown[] }).clients).toEqual(rows);

    const url = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(url).toContain(`tenant_id=eq.${tenantId}`);
    expect(url).toContain("client_type=eq.confidential");
    expect(url).not.toContain("client_secret_hash");
  });
});
