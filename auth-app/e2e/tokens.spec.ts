/**
 * E2E coverage for the OAuth token surface.
 *
 * Backed by an in-memory mock Supabase started in global-setup.ts so the
 * Next.js server-side fetches (handlers in lib/handlers/api-tokens and
 * lib/handlers/oauth) can land on real PostgREST-shaped responses without
 * needing a live database.
 *
 * Scenarios:
 *  - /api/tokens GET via wrapped session JWT (B2 regression guard)
 *
 * The opaque `bsv_sk_*` api_key lifecycle (issuance via POST /api/tokens
 * and introspect via the /api/tokens/introspect alias) was retired in
 * 2026-05-12. The RFC 8628 device-flow tests (and the B1 audience-format
 * regression suite) were retired in 2026-05-15 (Tier 3.1 Phase D) when
 * the device-flow endpoints were removed in favor of authorization_code
 * + PKCE on a loopback redirect. Coverage for the new flow lives in the
 * `_e2e` scenario harness (s3_authorization_code_flow,
 * s10_cli_loopback_flow).
 */

import { test, expect } from "@playwright/test";
import { TEST_USER_ACCESS_TOKEN } from "./mock-supabase/seed";

test.describe.configure({ mode: "serial" });


test.describe("/api/tokens accepts wrapped session JWT (B2 regression)", () => {
  // bsvibe-site /account/tokens proxy chain:
  //   cookie (refresh_token) → /api/session GET → wrapped session JWT
  //   (HS256, USER_JWT_SECRET) → /api/tokens with that Bearer
  // Pre-#15 the auth-app verifier only knew how to round-trip-verify
  // raw Supabase JWTs via /auth/v1/user → 401 "Invalid access_token"
  // for any wrapped JWT. The whole proxy was dead in prod.

  test("Bearer fallback /api/session → wrapped JWT → /api/tokens → 200", async ({
    request,
  }) => {
    // /api/session GET with Authorization: Bearer (Supabase raw JWT) hits
    // the Bearer fallback path that returns the raw access_token plus
    // a tenant context. We forward that to /api/tokens. This still
    // exercises the same auth-app verifier path the cookie flow uses,
    // since /api/tokens has no Bearer-specific shortcut.
    const sessionResp = await request.get("/api/session", {
      headers: { Authorization: `Bearer ${TEST_USER_ACCESS_TOKEN}` },
    });
    expect(sessionResp.status()).toBe(200);
    const sessionBody = await sessionResp.json();
    const accessToken = sessionBody.access_token as string;
    expect(typeof accessToken).toBe("string");

    const tokensResp = await request.get("/api/tokens", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(tokensResp.status()).toBe(200);
    const body = await tokensResp.json();
    expect(Array.isArray(body.tokens)).toBe(true);
  });

  test("raw Supabase Bearer → /api/tokens GET → 200 (no regression)", async ({
    request,
  }) => {
    const resp = await request.get("/api/tokens", {
      headers: { Authorization: `Bearer ${TEST_USER_ACCESS_TOKEN}` },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(Array.isArray(body.tokens)).toBe(true);
  });

  test("garbage Bearer → /api/tokens GET → 401 (no over-permissive fallback)", async ({
    request,
  }) => {
    // The local session-JWT verifier in #15 must reject signatures that
    // don't match USER_JWT_SECRET. Asserting 401 here pins the negative
    // path so a future "accept any JWT shape" regression is loud.
    const resp = await request.get("/api/tokens", {
      headers: { Authorization: "Bearer not-a-real-jwt" },
    });
    expect(resp.status()).toBe(401);
  });
});
