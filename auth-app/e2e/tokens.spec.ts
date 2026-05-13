/**
 * E2E coverage for the OAuth token surface.
 *
 * Backed by an in-memory mock Supabase started in global-setup.ts so the
 * Next.js server-side fetches (handlers in lib/handlers/api-tokens and
 * lib/handlers/oauth) can land on real PostgREST-shaped responses without
 * needing a live database.
 *
 * Scenarios:
 *  - Device flow: code → verify-page approve → token claim
 *  - Refresh token rotation
 *  - audience format coverage (B1 regression guard)
 *  - /api/tokens GET via wrapped session JWT (B2 regression guard)
 *
 * NOTE: The opaque `bsv_sk_*` api_key lifecycle (issuance via POST /api/tokens
 * and introspect via the /api/tokens/introspect alias) was retired in
 * 2026-05-12. PATs are now minted exclusively via the OAuth device flow.
 */

import { test, expect } from "@playwright/test";
import {
  TEST_DEVICE_CLIENT_ID,
  TEST_USER_ACCESS_TOKEN,
} from "./mock-supabase/seed";

const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

test.describe.configure({ mode: "serial" });

test.describe("device flow + refresh rotation", () => {
  let deviceCode: string;
  let userCode: string;
  let deviceAccessToken: string;
  let deviceRefreshToken: string;

  test("issue device_code + user_code", async ({ request }) => {
    const resp = await request.post("/api/oauth/device/code", {
      headers: { "Content-Type": "application/json" },
      data: {
        client_id: TEST_DEVICE_CLIENT_ID,
        scope: "gateway:models:read",
        audience: "gateway",
      },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.device_code).toBeTruthy();
    expect(body.user_code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
    expect(body.expires_in).toBe(600);
    expect(body.interval).toBe(5);
    deviceCode = body.device_code;
    userCode = body.user_code;
  });

  test("user approves via /oauth/device/verify UI", async ({ page }) => {
    // Stub /api/session at the browser boundary so the page bootstraps as
    // an authenticated user. The page then uses that access_token as the
    // Bearer for /api/oauth/device/verify, which the Next.js server validates
    // against the mock /auth/v1/user.
    await page.route("**/api/session", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          access_token: TEST_USER_ACCESS_TOKEN,
          refresh_token: "test-refresh",
          expires_in: 3600,
        }),
      }),
    );

    await page.goto(`/oauth/device/verify?user_code=${userCode}`);
    await expect(page.getByText(userCode)).toBeVisible();
    await page.getByRole("button", { name: /Approve/i }).click();
    await expect(page.getByText(/Approved\./)).toBeVisible();
  });

  test("device-grant token claim mints access_token + refresh_token", async ({
    request,
  }) => {
    const resp = await request.post("/api/oauth/device/token", {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      data: new URLSearchParams({
        grant_type: DEVICE_GRANT,
        device_code: deviceCode,
        client_id: TEST_DEVICE_CLIENT_ID,
      }).toString(),
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.token_type).toBe("Bearer");
    expect(typeof body.access_token).toBe("string");
    expect(body.access_token.split(".").length).toBe(3);
    expect(typeof body.refresh_token).toBe("string");
    deviceAccessToken = body.access_token;
    deviceRefreshToken = body.refresh_token;
  });

  test("replay device_code returns invalid_grant", async ({ request }) => {
    const resp = await request.post("/api/oauth/device/token", {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      data: new URLSearchParams({
        grant_type: DEVICE_GRANT,
        device_code: deviceCode,
        client_id: TEST_DEVICE_CLIENT_ID,
      }).toString(),
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.error).toBe("invalid_grant");
  });

  test("refresh_token grant rotates to a fresh pair", async ({ request }) => {
    expect(deviceAccessToken).toBeTruthy();
    const resp = await request.post("/api/oauth/token", {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      data: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: deviceRefreshToken,
      }).toString(),
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.token_type).toBe("Bearer");
    expect(typeof body.access_token).toBe("string");
    expect(typeof body.refresh_token).toBe("string");
    expect(body.refresh_token).not.toBe(deviceRefreshToken);
    expect(body.access_token).not.toBe(deviceAccessToken);
  });

  test("reusing the old refresh_token revokes the chain", async ({
    request,
  }) => {
    const resp = await request.post("/api/oauth/token", {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      data: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: deviceRefreshToken,
      }).toString(),
    });
    expect(resp.status()).toBe(401);
    const body = await resp.json();
    expect(body.error).toBe("invalid_grant");
  });
});

/**
 * Coverage added after the Phase 8 prod-escape post-mortem (May 9 2026).
 * Each describe-block here targets a specific bug class that slipped into
 * prod because no e2e exercised the exact request shape:
 *   - "audience format negative" → bug B1 (#13 — comma vs space split)
 *   - "/api/tokens via wrapped session JWT" → bug B2 (#15 — proxy 401)
 * If either describe-block disappears, the regression window reopens.
 */
test.describe("device/code body audience format coverage", () => {
  test("space-separated audience string → 200", async ({ request }) => {
    const resp = await request.post("/api/oauth/device/code", {
      headers: { "Content-Type": "application/json" },
      data: {
        client_id: TEST_DEVICE_CLIENT_ID,
        scope: "gateway:models:read",
        audience: "gateway",
      },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(typeof body.device_code).toBe("string");
    expect(typeof body.user_code).toBe("string");
  });

  test("comma-separated audience string → 200 (catches B1 regression)", async ({
    request,
  }) => {
    // bsvibe-cli-base login_cmd and bsvibe-site TokensList both default
    // to comma-separated audience. Pre-#13 the handler split body.audience
    // on `\s+` only and returned 400 invalid_target.
    const resp = await request.post("/api/oauth/device/code", {
      headers: { "Content-Type": "application/json" },
      data: {
        client_id: TEST_DEVICE_CLIENT_ID,
        scope: "gateway:models:read",
        audience: "gateway,gateway",
      },
    });
    expect(resp.status()).toBe(200);
  });

  test("unknown audience → 400 invalid_target (allowlist enforcement)", async ({
    request,
  }) => {
    const resp = await request.post("/api/oauth/device/code", {
      headers: { "Content-Type": "application/json" },
      data: {
        client_id: TEST_DEVICE_CLIENT_ID,
        scope: "gateway:models:read",
        audience: "definitely-not-a-real-audience",
      },
    });
    expect(resp.status()).toBe(400);
    const body = await resp.json();
    expect(body.error).toBe("invalid_target");
  });
});

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
