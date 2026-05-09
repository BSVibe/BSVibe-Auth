import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { verifySupabaseAccessToken } from "./_auth";

/**
 * Tests for the dual-path access-token verifier.
 *
 * Internal endpoints (/api/tokens, /api/tokens/[id], /api/tokens/introspect)
 * accept either:
 *   1. A *raw* Supabase user JWT, validated against `${SUPABASE_URL}/auth/v1/user`
 *   2. A *wrapped session JWT* issued by /api/session GET, signed locally
 *      with `USER_JWT_SECRET` (HS256). Subdomain consumers like bsvibe-site
 *      hold this token and shouldn't be forced to re-fetch the raw one.
 *
 * Path 1 is exercised via mocked fetch returning 200 + `{id}`.
 * Path 2 is exercised by signing a JWT with the same algorithm /api/session
 * uses and asserting the verifier extracts the `sub` after Supabase rejects.
 */

const TEST_USER_ID = "00000000-0000-4000-8000-000000000001";
const TEST_SECRET = "test-user-jwt-secret-256-bits-minimum-length-pad-pad-pad-pad";

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmacSha256Bytes(
  secret: string,
  message: string,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message),
  );
  return new Uint8Array(sig);
}

async function signSessionJwt(
  payload: Record<string, unknown>,
  secret = TEST_SECRET,
): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const headerB64 = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(header)),
  );
  const payloadB64 = base64UrlEncode(
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  const sig = await hmacSha256Bytes(secret, `${headerB64}.${payloadB64}`);
  return `${headerB64}.${payloadB64}.${base64UrlEncode(sig)}`;
}

describe("verifySupabaseAccessToken", () => {
  let envBackup: NodeJS.ProcessEnv;

  beforeEach(() => {
    envBackup = { ...process.env };
    process.env.USER_JWT_SECRET = TEST_SECRET;
  });

  afterEach(() => {
    process.env = envBackup;
    vi.restoreAllMocks();
  });

  it("returns user id when /auth/v1/user accepts the raw Supabase token", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ id: TEST_USER_ID }), { status: 200 }),
      );
    const result = await verifySupabaseAccessToken(
      { url: "https://supabase.test", anonKey: "anon" },
      "raw-supabase-jwt",
      fetchImpl as unknown as typeof fetch,
    );
    expect(result).toBe(TEST_USER_ID);
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("falls back to local session-JWT verification when Supabase rejects", async () => {
    const wrappedJwt = await signSessionJwt({
      sub: TEST_USER_ID,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(new Response("", { status: 401 }));
    const result = await verifySupabaseAccessToken(
      { url: "https://supabase.test", anonKey: "anon" },
      wrappedJwt,
      fetchImpl as unknown as typeof fetch,
    );
    expect(result).toBe(TEST_USER_ID);
  });

  it("returns null on session JWT signed with the wrong secret", async () => {
    const wrappedJwt = await signSessionJwt(
      { sub: TEST_USER_ID, exp: Math.floor(Date.now() / 1000) + 3600 },
      "different-secret",
    );
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(new Response("", { status: 401 }));
    const result = await verifySupabaseAccessToken(
      { url: "https://supabase.test", anonKey: "anon" },
      wrappedJwt,
      fetchImpl as unknown as typeof fetch,
    );
    expect(result).toBeNull();
  });

  it("returns null on expired session JWT", async () => {
    const wrappedJwt = await signSessionJwt({
      sub: TEST_USER_ID,
      exp: Math.floor(Date.now() / 1000) - 60,
    });
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(new Response("", { status: 401 }));
    const result = await verifySupabaseAccessToken(
      { url: "https://supabase.test", anonKey: "anon" },
      wrappedJwt,
      fetchImpl as unknown as typeof fetch,
    );
    expect(result).toBeNull();
  });

  it("returns null when both Supabase rejects and USER_JWT_SECRET is unset", async () => {
    delete process.env.USER_JWT_SECRET;
    const wrappedJwt = await signSessionJwt({ sub: TEST_USER_ID });
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(new Response("", { status: 401 }));
    const result = await verifySupabaseAccessToken(
      { url: "https://supabase.test", anonKey: "anon" },
      wrappedJwt,
      fetchImpl as unknown as typeof fetch,
    );
    expect(result).toBeNull();
  });

  it("returns null on malformed token (not 3 parts)", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(new Response("", { status: 401 }));
    const result = await verifySupabaseAccessToken(
      { url: "https://supabase.test", anonKey: "anon" },
      "not-a-jwt",
      fetchImpl as unknown as typeof fetch,
    );
    expect(result).toBeNull();
  });
});
