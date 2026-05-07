import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  createOAuthTokenHandler,
  type RefreshConsumeOutcome,
  type TokenRecord,
  type PatTokenInsertRow,
} from "./token";
import { makeReq, makeRes } from "../_lib/test-helpers";
import {
  decodeJwtPayload,
  type ServiceTokenPayload,
} from "../_lib/service-token";
import {
  hashClientSecret,
  type OAuthClientRecord,
} from "../_lib/oauth-client";
import {
  decodePatJwtPayload,
  verifyPatJwtSignature,
  type PatJwtPayload,
} from "../_lib/api-token";
import type { ClaimDeviceCodeOutcome } from "./device/token";
import type { AuditEmitInput } from "../_lib/audit-emit";

const baseEnv = {
  SUPABASE_URL: "https://test.supabase.co",
  SUPABASE_ANON_KEY: "anon-key",
  SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
  SERVICE_TOKEN_SIGNING_SECRET: "test-signing-secret-32-bytes-min!!",
  SERVICE_TOKEN_ISSUER: "https://auth.bsvibe.dev",
};

const tenantId = "98aafacf-ac62-479f-b8ab-21c0fe4e113e";
const validClientId = "bsgateway-prod";
const validClientSecret = "long-random-client-secret-of-yours";

async function buildClientRecord(
  overrides: Partial<OAuthClientRecord> = {},
): Promise<OAuthClientRecord> {
  return {
    client_id: validClientId,
    client_secret_hash: await hashClientSecret(validClientSecret),
    tenant_id: tenantId,
    allowed_audiences: ["bsupervisor"],
    allowed_scopes: ["bsupervisor.write", "bsupervisor.read"],
    revoked_at: null,
    ...overrides,
  };
}

function basicHeader(id: string, secret: string): string {
  return "Basic " + Buffer.from(`${id}:${secret}`).toString("base64");
}

describe("oauth/token handler", () => {
  let envBackup: NodeJS.ProcessEnv;

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });

  afterEach(() => {
    process.env = envBackup;
    vi.restoreAllMocks();
  });

  it("204 on OPTIONS preflight", async () => {
    const handler = createOAuthTokenHandler({
      lookupClient: vi.fn(),
    });
    const req = makeReq({ method: "OPTIONS" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(204);
  });

  it("405 on non-POST", async () => {
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({ method: "GET" });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(405);
  });

  it("400 invalid_request when grant_type missing", async () => {
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_request" });
  });

  it("400 unsupported_grant_type for non-client_credentials grants", async () => {
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { grant_type: "password", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "unsupported_grant_type" });
  });

  it("400 invalid_request when audience missing", async () => {
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { grant_type: "client_credentials" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_request" });
  });

  it("401 invalid_client when no credentials are provided", async () => {
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      body: { grant_type: "client_credentials", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
    expect(captured.headers["WWW-Authenticate"]).toBeDefined();
  });

  it("401 invalid_client when client does not exist", async () => {
    const lookupClient = vi.fn().mockResolvedValue(null);
    const handler = createOAuthTokenHandler({ lookupClient });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader("nope", "x") },
      body: { grant_type: "client_credentials", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
  });

  it("401 invalid_client when secret is wrong", async () => {
    const record = await buildClientRecord();
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, "wrong") },
      body: { grant_type: "client_credentials", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
  });

  it("401 invalid_client when client is revoked", async () => {
    const record = await buildClientRecord({
      revoked_at: "2026-01-01T00:00:00Z",
    });
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { grant_type: "client_credentials", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
  });

  it("400 invalid_target when audience is not in allowed_audiences", async () => {
    const record = await buildClientRecord({
      allowed_audiences: ["bsupervisor"],
    });
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { grant_type: "client_credentials", audience: "bsage" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_target" });
  });

  it("400 invalid_scope when requested scope is not allowed", async () => {
    const record = await buildClientRecord({
      allowed_scopes: ["bsupervisor.write"],
    });
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: {
        grant_type: "client_credentials",
        audience: "bsupervisor",
        scope: "bsupervisor.write bsupervisor.admin",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_scope" });
  });

  it("200 mints a service JWT with the requested scopes (client:<id> subject)", async () => {
    const record = await buildClientRecord();
    const lookupClient = vi.fn().mockResolvedValue(record);
    const touchLastUsed = vi.fn().mockResolvedValue(undefined);
    const handler = createOAuthTokenHandler({ lookupClient, touchLastUsed });

    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: {
        grant_type: "client_credentials",
        audience: "bsupervisor",
        scope: "bsupervisor.write",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as {
      access_token: string;
      expires_in: number;
      token_type: string;
      scope: string;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.scope).toBe("bsupervisor.write");

    const payload = decodeJwtPayload<ServiceTokenPayload>(body.access_token);
    expect(payload.aud).toBe("bsupervisor");
    expect(payload.sub).toBe(`client:${validClientId}`);
    expect(payload.tenant_id).toBe(tenantId);
    expect(payload.token_type).toBe("service");
    expect(payload.scope.split(" ").sort()).toEqual([
      "bsupervisor.write",
    ]);

    expect(touchLastUsed).toHaveBeenCalledWith(validClientId);
  });

  it("defaults scope to allowed_scopes when omitted", async () => {
    const record = await buildClientRecord({
      allowed_scopes: ["bsupervisor.write", "bsupervisor.read"],
    });
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });

    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { grant_type: "client_credentials", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as { scope: string; access_token: string };
    expect(body.scope.split(" ").sort()).toEqual([
      "bsupervisor.read",
      "bsupervisor.write",
    ]);
  });

  it("accepts client credentials in body (no Authorization header)", async () => {
    const record = await buildClientRecord();
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });

    const req = makeReq({
      method: "POST",
      body: {
        grant_type: "client_credentials",
        audience: "bsupervisor",
        client_id: validClientId,
        client_secret: validClientSecret,
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
  });

  it("accepts form-encoded payload (string body)", async () => {
    const record = await buildClientRecord();
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });

    const formBody = new URLSearchParams({
      grant_type: "client_credentials",
      audience: "bsupervisor",
      scope: "bsupervisor.write",
    }).toString();

    const req = makeReq({
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: basicHeader(validClientId, validClientSecret),
      },
      body: formBody,
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(200);
  });

  it("500 when SERVICE_TOKEN_SIGNING_SECRET is missing", async () => {
    delete process.env.SERVICE_TOKEN_SIGNING_SECRET;
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: { grant_type: "client_credentials", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(500);
  });
});

describe("oauth/token handler — refresh_token grant", () => {
  let envBackup: NodeJS.ProcessEnv;
  const userId = "33333333-3333-3333-3333-333333333333";
  const tokenId = "44444444-4444-4444-4444-444444444444";
  const refreshRaw = "the-old-refresh-token-raw-value";

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });
  afterEach(() => {
    process.env = envBackup;
    vi.restoreAllMocks();
  });

  function patTokenRecord(overrides: Partial<TokenRecord> = {}): TokenRecord {
    return {
      id: tokenId,
      user_id: userId,
      tenant_id: tenantId,
      type: "pat",
      audience: ["gateway"],
      scopes: ["gateway:models:read"],
      revoked_at: null,
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      ...overrides,
    };
  }

  it("400 invalid_request when refresh_token missing", async () => {
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      body: { grant_type: "refresh_token" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_request" });
  });

  it("200 mints new PAT + rotates refresh on valid refresh_token", async () => {
    const consumeRefreshToken = vi
      .fn<(rawToken: string) => Promise<RefreshConsumeOutcome>>()
      .mockResolvedValue({ kind: "consumed", tokenId, refreshId: "rt-old" });
    const getTokenRecord = vi
      .fn<(tokenId: string) => Promise<TokenRecord | null>>()
      .mockResolvedValue(patTokenRecord());
    const insertRefreshTokenRow = vi
      .fn<
        (
          tokenId: string,
          hash: Uint8Array,
          expiresAt: string,
        ) => Promise<boolean>
      >()
      .mockResolvedValue(true);
    const audits: AuditEmitInput[] = [];
    const emitAudit = vi
      .fn<(input: AuditEmitInput) => Promise<void>>()
      .mockImplementation(async (i) => {
        audits.push(i);
      });
    const handler = createOAuthTokenHandler({
      consumeRefreshToken,
      getTokenRecord,
      insertRefreshTokenRow,
      emitAudit,
    });

    const req = makeReq({
      method: "POST",
      body: { grant_type: "refresh_token", refresh_token: refreshRaw },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as {
      access_token: string;
      refresh_token: string;
      token_type: string;
      expires_in: number;
      scope: string;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.scope).toBe("gateway:models:read");
    expect(typeof body.refresh_token).toBe("string");
    expect(body.refresh_token).not.toBe(refreshRaw);

    const payload = decodePatJwtPayload<PatJwtPayload>(body.access_token);
    expect(payload.sub).toBe(userId);
    expect(payload.tenant).toBe(tenantId);
    expect(payload.aud).toEqual(["gateway"]);
    expect(payload.scope).toEqual(["gateway:models:read"]);
    expect(payload.token_type).toBe("pat");

    const sigOk = await verifyPatJwtSignature(
      body.access_token,
      baseEnv.SERVICE_TOKEN_SIGNING_SECRET,
    );
    expect(sigOk).toBe(true);

    expect(consumeRefreshToken).toHaveBeenCalledWith(refreshRaw);
    expect(getTokenRecord).toHaveBeenCalledWith(tokenId);
    expect(insertRefreshTokenRow).toHaveBeenCalledTimes(1);
    expect(audits.find((a) => a.eventType === "token.refreshed")).toBeTruthy();
  });

  it("401 invalid_grant + revokes parent token + emits race audit on reuse", async () => {
    const consumeRefreshToken = vi
      .fn<(rawToken: string) => Promise<RefreshConsumeOutcome>>()
      .mockResolvedValue({ kind: "race", tokenId });
    const getTokenRecord = vi
      .fn<(tokenId: string) => Promise<TokenRecord | null>>()
      .mockResolvedValue(patTokenRecord());
    const revokeTokenForRace = vi
      .fn<(tokenId: string) => Promise<void>>()
      .mockResolvedValue();
    const audits: AuditEmitInput[] = [];
    const emitAudit = vi
      .fn<(input: AuditEmitInput) => Promise<void>>()
      .mockImplementation(async (i) => {
        audits.push(i);
      });
    const handler = createOAuthTokenHandler({
      consumeRefreshToken,
      getTokenRecord,
      revokeTokenForRace,
      emitAudit,
    });
    const req = makeReq({
      method: "POST",
      body: { grant_type: "refresh_token", refresh_token: refreshRaw },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_grant" });
    expect(revokeTokenForRace).toHaveBeenCalledWith(tokenId);
    expect(
      audits.find((a) => a.eventType === "token.refresh_race_detected"),
    ).toBeTruthy();
  });

  it("401 invalid_grant on unknown/expired refresh_token", async () => {
    const consumeRefreshToken = vi
      .fn<(rawToken: string) => Promise<RefreshConsumeOutcome>>()
      .mockResolvedValue({ kind: "invalid" });
    const handler = createOAuthTokenHandler({ consumeRefreshToken });
    const req = makeReq({
      method: "POST",
      body: { grant_type: "refresh_token", refresh_token: "nope" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_grant" });
  });

  it("401 invalid_grant when parent token has been revoked", async () => {
    const consumeRefreshToken = vi
      .fn<(rawToken: string) => Promise<RefreshConsumeOutcome>>()
      .mockResolvedValue({ kind: "consumed", tokenId, refreshId: "rt-old" });
    const getTokenRecord = vi
      .fn<(tokenId: string) => Promise<TokenRecord | null>>()
      .mockResolvedValue(
        patTokenRecord({ revoked_at: "2026-01-01T00:00:00Z" }),
      );
    const handler = createOAuthTokenHandler({
      consumeRefreshToken,
      getTokenRecord,
    });
    const req = makeReq({
      method: "POST",
      body: { grant_type: "refresh_token", refresh_token: refreshRaw },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_grant" });
  });
});

describe("oauth/token handler — device_code grant", () => {
  let envBackup: NodeJS.ProcessEnv;
  const userId = "55555555-5555-5555-5555-555555555555";
  const deviceCode = "the-device-code-43-bytes-base64url-x";

  beforeEach(() => {
    envBackup = { ...process.env };
    Object.assign(process.env, baseEnv);
  });
  afterEach(() => {
    process.env = envBackup;
    vi.restoreAllMocks();
  });

  async function buildClient(): Promise<OAuthClientRecord> {
    return {
      client_id: "device-flow-cli",
      client_secret_hash: await hashClientSecret("ignored-for-device-flow"),
      tenant_id: tenantId,
      allowed_audiences: ["gateway"],
      allowed_scopes: ["gateway:models:read"],
      revoked_at: null,
    };
  }

  it("400 invalid_request when device_code or client_id missing", async () => {
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_request" });
  });

  it("200 mints PAT + refresh on claimed device_code", async () => {
    const lookupClient = vi.fn().mockResolvedValue(await buildClient());
    const claimDeviceCode = vi
      .fn<
        (
          deviceCode: string,
          clientId: string,
        ) => Promise<ClaimDeviceCodeOutcome>
      >()
      .mockResolvedValue({
        kind: "claimed",
        userId,
        scope: ["gateway:models:read"],
        audience: ["gateway"],
        clientId: "device-flow-cli",
      });
    const insertPatTokenRow = vi
      .fn<(row: PatTokenInsertRow) => Promise<boolean>>()
      .mockResolvedValue(true);
    const insertRefreshTokenRow = vi
      .fn<
        (
          tokenId: string,
          hash: Uint8Array,
          expiresAt: string,
        ) => Promise<boolean>
      >()
      .mockResolvedValue(true);
    const audits: AuditEmitInput[] = [];
    const emitAudit = vi
      .fn<(input: AuditEmitInput) => Promise<void>>()
      .mockImplementation(async (i) => {
        audits.push(i);
      });
    const handler = createOAuthTokenHandler({
      lookupClient,
      claimDeviceCode,
      insertPatTokenRow,
      insertRefreshTokenRow,
      emitAudit,
    });

    const req = makeReq({
      method: "POST",
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: "device-flow-cli",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(200);
    const body = captured.body as {
      access_token: string;
      refresh_token: string;
      token_type: string;
      expires_in: number;
      scope: string;
    };
    expect(body.token_type).toBe("Bearer");
    expect(body.scope).toBe("gateway:models:read");
    const payload = decodePatJwtPayload<PatJwtPayload>(body.access_token);
    expect(payload.sub).toBe(userId);
    expect(payload.tenant).toBe(tenantId);
    expect(payload.aud).toEqual(["gateway"]);
    expect(payload.token_type).toBe("pat");

    expect(claimDeviceCode).toHaveBeenCalledWith(deviceCode, "device-flow-cli");
    expect(insertPatTokenRow).toHaveBeenCalledTimes(1);
    expect(insertRefreshTokenRow).toHaveBeenCalledTimes(1);
    expect(audits.find((a) => a.eventType === "token.created")).toBeTruthy();
  });

  it("400 authorization_pending when device claim still pending", async () => {
    const lookupClient = vi.fn().mockResolvedValue(await buildClient());
    const claimDeviceCode = vi
      .fn<
        (
          deviceCode: string,
          clientId: string,
        ) => Promise<ClaimDeviceCodeOutcome>
      >()
      .mockResolvedValue({ kind: "pending" });
    const handler = createOAuthTokenHandler({
      lookupClient,
      claimDeviceCode,
    });
    const req = makeReq({
      method: "POST",
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: "device-flow-cli",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "authorization_pending" });
  });

  it("400 access_denied when user denied", async () => {
    const lookupClient = vi.fn().mockResolvedValue(await buildClient());
    const claimDeviceCode = vi
      .fn<
        (
          deviceCode: string,
          clientId: string,
        ) => Promise<ClaimDeviceCodeOutcome>
      >()
      .mockResolvedValue({ kind: "denied" });
    const handler = createOAuthTokenHandler({
      lookupClient,
      claimDeviceCode,
    });
    const req = makeReq({
      method: "POST",
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: "device-flow-cli",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "access_denied" });
  });

  it("400 expired_token when device row past expiry", async () => {
    const lookupClient = vi.fn().mockResolvedValue(await buildClient());
    const claimDeviceCode = vi
      .fn<
        (
          deviceCode: string,
          clientId: string,
        ) => Promise<ClaimDeviceCodeOutcome>
      >()
      .mockResolvedValue({ kind: "expired" });
    const handler = createOAuthTokenHandler({
      lookupClient,
      claimDeviceCode,
    });
    const req = makeReq({
      method: "POST",
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: "device-flow-cli",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "expired_token" });
  });

  it("400 invalid_grant on consumed/replay device_code", async () => {
    const lookupClient = vi.fn().mockResolvedValue(await buildClient());
    const claimDeviceCode = vi
      .fn<
        (
          deviceCode: string,
          clientId: string,
        ) => Promise<ClaimDeviceCodeOutcome>
      >()
      .mockResolvedValue({ kind: "consumed" });
    const handler = createOAuthTokenHandler({
      lookupClient,
      claimDeviceCode,
    });
    const req = makeReq({
      method: "POST",
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: "device-flow-cli",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_grant" });
  });

  it("401 invalid_client when client unknown for device grant", async () => {
    const lookupClient = vi.fn().mockResolvedValue(null);
    const handler = createOAuthTokenHandler({ lookupClient });
    const req = makeReq({
      method: "POST",
      body: {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: "ghost",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
  });
});
