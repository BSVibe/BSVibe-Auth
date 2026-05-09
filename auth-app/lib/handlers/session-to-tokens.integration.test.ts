import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createSessionHandler } from "./session";
import { createListTokensHandler } from "./api-tokens/list";
import { makeReq, makeRes } from "./_lib/test-helpers";

/**
 * Integration test — wraps the actual surface that bsvibe-site's
 * /account/tokens proxy hits. Catches the class of bug that PR #15
 * fixed: /api/session GET returns a wrapped session JWT, the proxy
 * forwards it to /api/tokens, and /api/tokens MUST accept it.
 *
 * The unit tests for each handler in isolation passed (they mock
 * verifyAccessToken). This test wires the *real* verify path so that
 * if /api/tokens ever again rejects the token /api/session emitted,
 * the regression surfaces here — not in prod after a redeploy round-
 * trip. Pre-merge contract: cross-handler flows that ship together
 * get an integration-level test, not just per-handler unit tests.
 */

const TEST_USER_ID = "00000000-0000-4000-8000-000000000001";
const TEST_USER_JWT_SECRET =
  "test-user-jwt-secret-256-bits-minimum-length-pad-pad-pad-pad";
const TEST_REFRESH_TOKEN = "test-refresh-token";

function b64url(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// A *shape-valid* unsigned-from-our-perspective JWT — issueSessionJwt
// only cares that the payload decodes and carries `sub`. Supabase's
// /auth/v1/user is stubbed below so the signature itself is never
// re-verified through this token path.
const TEST_SUPABASE_RAW_AT = `${b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64url(JSON.stringify({ sub: TEST_USER_ID, exp: Math.floor(Date.now() / 1000) + 3600 }))}.signature-placeholder`;

// Stub Supabase: GET /auth/v1/user → 200 only when given the raw token.
//                POST /auth/v1/token → returns raw access_token + refresh_token.
function buildSupabaseStub(): typeof fetch {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.endsWith("/auth/v1/user")) {
      const auth = (init?.headers as Record<string, string>)?.Authorization;
      if (auth === `Bearer ${TEST_SUPABASE_RAW_AT}`) {
        return new Response(JSON.stringify({ id: TEST_USER_ID }), {
          status: 200,
        });
      }
      return new Response("", { status: 401 });
    }
    if (url.includes("/auth/v1/token?grant_type=refresh_token")) {
      return new Response(
        JSON.stringify({
          access_token: TEST_SUPABASE_RAW_AT,
          refresh_token: TEST_REFRESH_TOKEN,
          expires_in: 3600,
        }),
        { status: 200 },
      );
    }
    if (url.includes("/rest/v1/tokens")) {
      // /api/tokens proxies a SELECT against PostgREST; return empty list.
      return new Response("[]", { status: 200 });
    }
    return new Response("not handled in stub", { status: 500 });
  }) as unknown as typeof fetch;
}

describe("session → /api/tokens integration (wrapped session JWT)", () => {
  let envBackup: NodeJS.ProcessEnv;

  beforeEach(() => {
    envBackup = { ...process.env };
    process.env.SUPABASE_URL = "https://supabase.test";
    process.env.SUPABASE_ANON_KEY = "anon-key";
    process.env.SUPABASE_SERVICE_ROLE_KEY = "service-role-key";
    process.env.USER_JWT_SECRET = TEST_USER_JWT_SECRET;
  });

  afterEach(() => {
    process.env = envBackup;
    vi.restoreAllMocks();
  });

  it("/api/session GET → wrapped JWT → /api/tokens accepts it (+200 list)", async () => {
    const fetchImpl = buildSupabaseStub();

    // 1) /api/session GET — produces the wrapped session JWT.
    const sessionHandler = createSessionHandler({
      fetchImpl,
      listTenantsForUser: async () => [],
    });
    const sessionReq = makeReq({
      method: "GET",
      headers: { cookie: `bsvibe_session=${TEST_REFRESH_TOKEN}` },
    });
    const { res: sessionRes, captured: sessionCap } = makeRes();
    await sessionHandler(sessionReq, sessionRes);
    expect(sessionCap.statusCode).toBe(200);
    const sessionBody = sessionCap.body as { access_token?: string };
    const wrappedJwt = sessionBody.access_token;
    expect(wrappedJwt).toBeTruthy();
    expect(wrappedJwt).not.toBe(TEST_SUPABASE_RAW_AT); // really wrapped, not pass-through

    // 2) bsvibe-site proxy → /api/tokens with the wrapped JWT.
    const listHandler = createListTokensHandler({ fetchImpl });
    const tokensReq = makeReq({
      method: "GET",
      headers: { authorization: `Bearer ${wrappedJwt}` },
      query: { type: "pat" },
    });
    const { res: tokensRes, captured: tokensCap } = makeRes();
    await listHandler(tokensReq, tokensRes);

    expect(tokensCap.statusCode).toBe(200);
    expect(tokensCap.body).toEqual({ tokens: [] });
  });

  it("raw Supabase JWT still works against /api/tokens (no regression)", async () => {
    const fetchImpl = buildSupabaseStub();
    const listHandler = createListTokensHandler({ fetchImpl });
    const tokensReq = makeReq({
      method: "GET",
      headers: { authorization: `Bearer ${TEST_SUPABASE_RAW_AT}` },
      query: { type: "pat" },
    });
    const { res, captured } = makeRes();
    await listHandler(tokensReq, res);
    expect(captured.statusCode).toBe(200);
    expect(captured.body).toEqual({ tokens: [] });
  });

  it("garbage Bearer → 401, not 200 (no over-permissive fallback)", async () => {
    const fetchImpl = buildSupabaseStub();
    const listHandler = createListTokensHandler({ fetchImpl });
    const tokensReq = makeReq({
      method: "GET",
      headers: { authorization: "Bearer garbage" },
    });
    const { res, captured } = makeRes();
    await listHandler(tokensReq, res);
    expect(captured.statusCode).toBe(401);
  });
});
