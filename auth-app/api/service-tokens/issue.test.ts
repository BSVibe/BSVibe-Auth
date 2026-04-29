import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createIssueServiceTokenHandler } from "./issue";
import { makeReq, makeRes } from "../_lib/test-helpers";
import {
  decodeJwtPayload,
  type ServiceTokenPayload,
} from "../_lib/service-token";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
  SERVICE_TOKEN_SIGNING_SECRET: "test-signing-secret-32-bytes-min!!",
  SERVICE_TOKEN_ISSUER: "https://auth.bsvibe.dev",
};

// Token for user "user-abc" with active tenant "t1"
const USER_TOKEN =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJzdWIiOiJ1c2VyLWFiYyIsImVtYWlsIjoiYUBiLmMiLCJleHAiOjk5OTk5OTk5OTl9." +
  "sig";

describe("service-tokens/issue handler", () => {
  let envBackup: NodeJS.ProcessEnv;
  const verifyAccessToken = vi.fn().mockResolvedValue("user-abc");

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
    verifyAccessToken.mockResolvedValue("user-abc");
  });

  afterEach(() => {
    process.env = envBackup;
  });

  it("returns 405 for non-POST", async () => {
    const handler = createIssueServiceTokenHandler({ getMembership: vi.fn() });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("returns 401 when no Authorization header", async () => {
    const handler = createIssueServiceTokenHandler({ getMembership: vi.fn() });
    const req = makeReq({
      method: "POST",
      body: {
        audience: "bsage",
        scope: ["bsage.read"],
        tenant_id: "t1",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
  });

  it("returns 400 when audience missing", async () => {
    const handler = createIssueServiceTokenHandler({
      verifyAccessToken,
      getMembership: vi.fn().mockResolvedValue("owner"),
    });
    const req = makeReq({
      method: "POST",
      body: { scope: ["bsage.read"], tenant_id: "t1" },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("returns 400 when audience invalid", async () => {
    const handler = createIssueServiceTokenHandler({
      verifyAccessToken,
      getMembership: vi.fn().mockResolvedValue("owner"),
    });
    const req = makeReq({
      method: "POST",
      body: { audience: "unknown", scope: ["unknown.read"], tenant_id: "t1" },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("returns 400 when scope mismatches audience", async () => {
    const handler = createIssueServiceTokenHandler({
      verifyAccessToken,
      getMembership: vi.fn().mockResolvedValue("owner"),
    });
    const req = makeReq({
      method: "POST",
      body: {
        audience: "bsage",
        scope: ["bsgateway.read"],
        tenant_id: "t1",
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("returns 403 when caller is not a member of tenant_id", async () => {
    const getMembership = vi.fn().mockResolvedValue(null);
    const handler = createIssueServiceTokenHandler({ verifyAccessToken, getMembership });
    const req = makeReq({
      method: "POST",
      body: {
        audience: "bsage",
        scope: ["bsage.read"],
        tenant_id: "t1",
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
  });

  it("returns 403 when caller role is below admin (member)", async () => {
    const getMembership = vi.fn().mockResolvedValue("member");
    const handler = createIssueServiceTokenHandler({ verifyAccessToken, getMembership });
    const req = makeReq({
      method: "POST",
      body: {
        audience: "bsage",
        scope: ["bsage.read"],
        tenant_id: "t1",
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
  });

  it("returns 403 when caller role is viewer", async () => {
    const getMembership = vi.fn().mockResolvedValue("viewer");
    const handler = createIssueServiceTokenHandler({ verifyAccessToken, getMembership });
    const req = makeReq({
      method: "POST",
      body: {
        audience: "bsage",
        scope: ["bsage.read"],
        tenant_id: "t1",
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(403);
  });

  it("issues a token when caller is owner", async () => {
    const getMembership = vi.fn().mockResolvedValue("owner");
    const handler = createIssueServiceTokenHandler({ verifyAccessToken, getMembership });
    const req = makeReq({
      method: "POST",
      body: {
        audience: "bsage",
        scope: ["bsage.read", "bsage.write"],
        tenant_id: "t1",
        ttl_s: 7200,
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as {
      access_token: string;
      expires_in: number;
      token_type: string;
    };
    expect(typeof body.access_token).toBe("string");
    expect(body.access_token.split(".")).toHaveLength(3);
    expect(body.expires_in).toBe(7200);
    expect(body.token_type).toBe("service");

    const payload = decodeJwtPayload<ServiceTokenPayload>(body.access_token);
    expect(payload.aud).toBe("bsage");
    expect(payload.scope).toBe("bsage.read bsage.write");
    expect(payload.token_type).toBe("service");
    expect(payload.tenant_id).toBe("t1");
    // Subject = "user:<userId>" because the token was issued by a user (delegated).
    expect(payload.sub).toBe("user:user-abc");
    expect(payload.iss).toBe(baseEnv.SERVICE_TOKEN_ISSUER);

    expect(getMembership).toHaveBeenCalledWith(
      expect.objectContaining({ url: baseEnv.SUPABASE_URL }),
      "user-abc",
      "t1",
      expect.anything(),
    );
  });

  it("issues a token when caller is admin", async () => {
    const getMembership = vi.fn().mockResolvedValue("admin");
    const handler = createIssueServiceTokenHandler({ verifyAccessToken, getMembership });
    const req = makeReq({
      method: "POST",
      body: {
        audience: "bsnexus",
        scope: ["bsnexus.read"],
        tenant_id: "t1",
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
    const body = captured.body as { expires_in: number };
    expect(body.expires_in).toBe(3600); // default TTL
  });

  it("returns 400 when tenant_id is missing", async () => {
    const handler = createIssueServiceTokenHandler({
      verifyAccessToken,
      getMembership: vi.fn().mockResolvedValue("owner"),
    });
    const req = makeReq({
      method: "POST",
      body: { audience: "bsage", scope: ["bsage.read"] },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("returns 400 for invalid TTL", async () => {
    const handler = createIssueServiceTokenHandler({
      verifyAccessToken,
      getMembership: vi.fn().mockResolvedValue("owner"),
    });
    const req = makeReq({
      method: "POST",
      body: {
        audience: "bsage",
        scope: ["bsage.read"],
        tenant_id: "t1",
        ttl_s: 30, // below MIN
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
  });

  it("returns 500 when SERVICE_TOKEN_SIGNING_SECRET not configured", async () => {
    delete process.env.SERVICE_TOKEN_SIGNING_SECRET;
    const handler = createIssueServiceTokenHandler({
      verifyAccessToken,
      getMembership: vi.fn().mockResolvedValue("owner"),
    });
    const req = makeReq({
      method: "POST",
      body: {
        audience: "bsage",
        scope: ["bsage.read"],
        tenant_id: "t1",
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(500);
  });

  it("returns 401 and skips membership lookup when access token verification fails", async () => {
    verifyAccessToken.mockResolvedValueOnce(null);
    const getMembership = vi.fn().mockResolvedValue("owner");
    const handler = createIssueServiceTokenHandler({ verifyAccessToken, getMembership });
    const req = makeReq({
      method: "POST",
      body: {
        audience: "bsage",
        scope: ["bsage.read"],
        tenant_id: "t1",
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(401);
    expect(getMembership).not.toHaveBeenCalled();
  });

  it("issues bsvibe-auth audit.write tokens for audit ingestion", async () => {
    const handler = createIssueServiceTokenHandler({
      verifyAccessToken,
      getMembership: vi.fn().mockResolvedValue("owner"),
    });
    const req = makeReq({
      method: "POST",
      body: {
        audience: "bsvibe-auth",
        scope: ["audit.write"],
        tenant_id: "t1",
      },
      headers: { authorization: `Bearer ${USER_TOKEN}` },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as { access_token: string };
    const payload = decodeJwtPayload<ServiceTokenPayload>(body.access_token);
    expect(payload.aud).toBe("bsvibe-auth");
    expect(payload.scope).toBe("audit.write");
  });
});
