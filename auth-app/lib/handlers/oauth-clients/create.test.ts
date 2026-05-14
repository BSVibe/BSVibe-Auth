import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { createOAuthClientHandler } from "./create";
import { makeReq, makeRes } from "../_lib/test-helpers";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
};

const userId = "00000000-0000-0000-0000-000000000001";
const tenantId = "10000000-0000-0000-0000-000000000010";

function authedReq(body: unknown) {
  return makeReq({
    method: "POST",
    headers: {
      authorization: "Bearer user-access-token",
      "content-type": "application/json",
    },
    body,
  });
}

describe("oauth-clients/create handler", () => {
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
    const handler = createOAuthClientHandler({
      verifyAccessToken: vi.fn(),
    });
    const req = makeReq({ method: "POST", body: {} });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("400 when name missing", async () => {
    const handler = createOAuthClientHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(userId),
    });
    const req = authedReq({
      allowed_audiences: ["bsgateway"],
      allowed_scopes: ["bsgateway:read"],
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect((captured.body as { error: string }).error).toBe("invalid_request");
  });

  it("400 when audience unknown", async () => {
    const handler = createOAuthClientHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(userId),
    });
    const req = authedReq({
      name: "ci",
      allowed_audiences: ["nonsense"],
      allowed_scopes: ["bsgateway:read"],
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("400 when scope malformed", async () => {
    const handler = createOAuthClientHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(userId),
    });
    const req = authedReq({
      name: "ci",
      allowed_audiences: ["bsgateway"],
      allowed_scopes: ["NO_COLON"],
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("403 when user has no tenant membership", async () => {
    const handler = createOAuthClientHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(userId),
      resolveTenantId: vi.fn().mockResolvedValue(null),
    });
    const req = authedReq({
      name: "ci",
      allowed_audiences: ["bsgateway"],
      allowed_scopes: ["bsgateway:read"],
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
  });

  it("201 mints client + returns plaintext secret once", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [
        {
          client_id: "svc-deadbeefdeadbeef",
          description: "ci",
          tenant_id: tenantId,
          allowed_audiences: ["bsgateway"],
          allowed_scopes: ["bsgateway:read"],
          created_at: "2026-05-12T00:00:00Z",
        },
      ],
    }) as unknown as typeof fetch;
    const audits: unknown[] = [];
    const handler = createOAuthClientHandler({
      verifyAccessToken: vi.fn().mockResolvedValue(userId),
      resolveTenantId: vi.fn().mockResolvedValue(tenantId),
      fetchImpl,
      emitAudit: async (i) => {
        audits.push(i);
      },
      generateClientId: () => "svc-deadbeefdeadbeef",
      generateClientSecret: () =>
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0123456789",
    });
    const req = authedReq({
      name: "ci",
      allowed_audiences: ["bsgateway"],
      allowed_scopes: ["bsgateway:read"],
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(201);
    const body = captured.body as {
      client_id: string;
      client_secret: string;
      tenant_id: string;
      allowed_audiences: string[];
      allowed_scopes: string[];
    };
    expect(body.client_id).toBe("svc-deadbeefdeadbeef");
    expect(body.client_secret).toBe(
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0123456789",
    );
    expect(body.tenant_id).toBe(tenantId);
    expect(body.allowed_audiences).toEqual(["bsgateway"]);
    expect(body.allowed_scopes).toEqual(["bsgateway:read"]);
    // Audit fired.
    expect(audits.length).toBe(1);
    // Insert call inspected — must NOT carry plaintext, must carry PBKDF2 hash.
    const insertCall = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0];
    const init = insertCall[1] as RequestInit;
    const sent = JSON.parse(init.body as string);
    expect(sent.client_secret_hash.startsWith("pbkdf2-sha256$")).toBe(true);
    expect(sent.client_type).toBe("confidential");
    expect(sent.tenant_id).toBe(tenantId);
  });
});
