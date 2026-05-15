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
import type { ClaimAuthorizationCodeOutcome } from "./authorization_code";
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
    client_type: "confidential",
    client_secret_hash: await hashClientSecret(validClientSecret),
    tenant_id: tenantId,
    allowed_audiences: ["bsupervisor"],
    allowed_scopes: ["bsupervisor:write", "bsupervisor:read"],
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

  it("400 unauthorized_client when public client tries client_credentials", async () => {
    // Public RFC 8252 native-app clients (e.g. the canonical `cli` row)
    // ship with no secret and may only mint PATs via the authorization_code
    // grant. Reaching the client_credentials path with one is a configuration
    // bug that must surface with a distinct error code, not the generic
    // `invalid_client` we'd emit for a wrong secret.
    const record = await buildClientRecord({
      client_type: "public",
      client_secret_hash: null,
      tenant_id: null,
    });
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });
    const req = makeReq({
      method: "POST",
      headers: {
        authorization: basicHeader(validClientId, "any-secret-the-cli-might-send"),
      },
      body: { grant_type: "client_credentials", audience: "bsupervisor" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "unauthorized_client" });
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
      allowed_scopes: ["bsupervisor:write"],
    });
    const lookupClient = vi.fn().mockResolvedValue(record);
    const handler = createOAuthTokenHandler({ lookupClient });
    const req = makeReq({
      method: "POST",
      headers: { authorization: basicHeader(validClientId, validClientSecret) },
      body: {
        grant_type: "client_credentials",
        audience: "bsupervisor",
        scope: "bsupervisor:write bsage:read",
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
        scope: "bsupervisor:write",
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
    expect(body.scope).toBe("bsupervisor:write");

    const payload = decodeJwtPayload<ServiceTokenPayload>(body.access_token);
    expect(payload.aud).toBe("bsupervisor");
    expect(payload.sub).toBe(`client:${validClientId}`);
    expect(payload.tenant_id).toBe(tenantId);
    expect(payload.token_type).toBe("service");
    expect(payload.scope.split(" ").sort()).toEqual([
      "bsupervisor:write",
    ]);

    expect(touchLastUsed).toHaveBeenCalledWith(validClientId);
  });

  it("defaults scope to allowed_scopes when omitted", async () => {
    const record = await buildClientRecord({
      allowed_scopes: ["bsupervisor:write", "bsupervisor:read"],
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
      "bsupervisor:read",
      "bsupervisor:write",
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
      scope: "bsupervisor:write",
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
      audience: ["bsgateway"],
      scopes: ["bsgateway:models:read"],
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
    expect(body.scope).toBe("bsgateway:models:read");
    expect(typeof body.refresh_token).toBe("string");
    expect(body.refresh_token).not.toBe(refreshRaw);

    const payload = decodePatJwtPayload<PatJwtPayload>(body.access_token);
    expect(payload.sub).toBe(userId);
    expect(payload.tenant).toBe(tenantId);
    expect(payload.aud).toEqual(["bsgateway"]);
    expect(payload.scope).toEqual(["bsgateway:models:read"]);
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

describe("oauth/token handler — authorization_code grant", () => {
  let envBackup: NodeJS.ProcessEnv;
  const userId = "66666666-6666-6666-6666-666666666666";
  const userTenantId = "77777777-7777-7777-7777-777777777777";
  const code = "test-authz-code-43chars-base64url-aaaaaaaaaa";
  const redirectUri = "http://127.0.0.1:54321/callback";
  const codeVerifier = "test-verifier-43chars-mlnopqrstuvwxyz0123456789AAA";

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
      client_id: "claude-code-mcp",
      client_type: "public",
      client_secret_hash: null,
      tenant_id: null,
      allowed_audiences: ["bsgateway", "bsage"],
      allowed_scopes: ["bsgateway:*", "bsage:*"],
      redirect_uris: [redirectUri],
      revoked_at: null,
    };
  }

  it("400 invalid_request when code/redirect_uri/code_verifier missing", async () => {
    const handler = createOAuthTokenHandler({ lookupClient: vi.fn() });
    const req = makeReq({
      method: "POST",
      body: { grant_type: "authorization_code", client_id: "claude-code-mcp" },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({ error: "invalid_request" });
  });

  it("401 invalid_client when client unknown", async () => {
    const handler = createOAuthTokenHandler({
      lookupClient: vi.fn().mockResolvedValue(null),
    });
    const req = makeReq({
      method: "POST",
      body: {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
        client_id: "ghost",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);
    expect(captured.statusCode).toBe(401);
    expect(captured.body).toMatchObject({ error: "invalid_client" });
  });

  it("400 invalid_grant on PKCE mismatch", async () => {
    const lookupClient = vi.fn().mockResolvedValue(await buildClient());
    const claimAuthorizationCode = vi
      .fn<
        (input: {
          code: string;
          expectedClientId: string;
          redirectUri: string;
          codeVerifier: string;
        }) => Promise<ClaimAuthorizationCodeOutcome>
      >()
      .mockResolvedValue({ kind: "pkce_mismatch" });
    const handler = createOAuthTokenHandler({
      lookupClient,
      claimAuthorizationCode,
    });

    const req = makeReq({
      method: "POST",
      body: {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
        client_id: "claude-code-mcp",
      },
    });
    const { res, captured } = makeRes();
    await handler(req, res);

    expect(captured.statusCode).toBe(400);
    expect(captured.body).toMatchObject({
      error: "invalid_grant",
      error_description: "authorization code pkce mismatch",
    });
  });

  it.each([
    ["not_found", "authorization code not found"],
    ["used", "authorization code used"],
    ["expired", "authorization code expired"],
    ["client_mismatch", "authorization code client mismatch"],
    ["redirect_uri_mismatch", "authorization code redirect uri mismatch"],
  ] as const)(
    "400 invalid_grant surfaces outcome '%s' as error_description",
    async (kind, description) => {
      const lookupClient = vi.fn().mockResolvedValue(await buildClient());
      const claimAuthorizationCode = vi
        .fn<
          (input: {
            code: string;
            expectedClientId: string;
            redirectUri: string;
            codeVerifier: string;
          }) => Promise<ClaimAuthorizationCodeOutcome>
        >()
        .mockResolvedValue({ kind } as ClaimAuthorizationCodeOutcome);
      const handler = createOAuthTokenHandler({
        lookupClient,
        claimAuthorizationCode,
      });
      const req = makeReq({
        method: "POST",
        body: {
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri,
          code_verifier: codeVerifier,
          client_id: "claude-code-mcp",
        },
      });
      const { res, captured } = makeRes();
      await handler(req, res);
      expect(captured.statusCode).toBe(400);
      expect(captured.body).toMatchObject({
        error: "invalid_grant",
        error_description: description,
      });
    },
  );

  it("200 mints PAT + refresh on claimed authorization_code", async () => {
    const lookupClient = vi.fn().mockResolvedValue(await buildClient());
    const claimAuthorizationCode = vi
      .fn<
        (input: {
          code: string;
          expectedClientId: string;
          redirectUri: string;
          codeVerifier: string;
        }) => Promise<ClaimAuthorizationCodeOutcome>
      >()
      .mockResolvedValue({
        kind: "claimed",
        clientId: "claude-code-mcp",
        userId,
        tenantId: userTenantId,
        scope: ["bsgateway:*"],
        audience: ["bsgateway"],
        redirectUri,
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
      claimAuthorizationCode,
      insertPatTokenRow,
      insertRefreshTokenRow,
      emitAudit,
    });

    const req = makeReq({
      method: "POST",
      body: {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
        client_id: "claude-code-mcp",
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
    expect(body.scope).toBe("bsgateway:*");
    expect(body.expires_in).toBe(30 * 24 * 60 * 60);
    const payload = decodePatJwtPayload<PatJwtPayload>(body.access_token);
    expect(payload.sub).toBe(userId);
    expect(payload.tenant).toBe(userTenantId);
    expect(payload.aud).toEqual(["bsgateway"]);
    expect(payload.token_type).toBe("pat");
    expect(
      audits.find(
        (a) =>
          a.eventType === "token.created" &&
          (a.data as { grant?: string }).grant === "authorization_code",
      ),
    ).toBeTruthy();
    expect(insertPatTokenRow).toHaveBeenCalledTimes(1);
    expect(insertRefreshTokenRow).toHaveBeenCalledTimes(1);
    expect(
      await verifyPatJwtSignature(
        body.access_token,
        baseEnv.SERVICE_TOKEN_SIGNING_SECRET,
      ),
    ).toBe(true);
  });
});
