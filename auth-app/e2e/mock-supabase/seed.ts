/**
 * Seed values + helpers for the e2e mock Supabase server.
 *
 * Constants are deterministic so tests can construct Bearer/Basic credentials
 * up front. The PBKDF2 hash format mirrors lib/handlers/_lib/oauth-client.ts:
 *   pbkdf2-sha256$<iterations>$<salt-b64url>$<hash-b64url>
 */

import { pbkdf2Sync, randomBytes } from "node:crypto";

export const TEST_USER_ID = "00000000-0000-4000-8000-000000000001";
export const TEST_TENANT_ID = "00000000-0000-4000-8000-000000000002";
export const TEST_USER_ACCESS_TOKEN = "test-user-access-token-1";

export const TEST_OAUTH_CLIENT_ID = "test-rs";
export const TEST_OAUTH_CLIENT_SECRET = "test-rs-secret-do-not-use-in-prod";

export const TEST_DEVICE_CLIENT_ID = "test-device";

export const TEST_SUPABASE_SERVICE_ROLE_KEY = "test-service-role-key";
export const TEST_SUPABASE_ANON_KEY = "test-anon-key";
export const TEST_SERVICE_TOKEN_SIGNING_SECRET =
  "test-service-token-signing-secret-256-bits-minimum-length-pad-pad-pad";

const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_SALT_BYTES = 16;
const PBKDF2_HASH_BYTES = 32;

function base64UrlEncode(bytes: Buffer): string {
  return bytes
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function hashClientSecretSync(plain: string): string {
  const salt = randomBytes(PBKDF2_SALT_BYTES);
  const hash = pbkdf2Sync(
    plain,
    salt,
    PBKDF2_ITERATIONS,
    PBKDF2_HASH_BYTES,
    "sha256",
  );
  return [
    "pbkdf2-sha256",
    PBKDF2_ITERATIONS,
    base64UrlEncode(salt),
    base64UrlEncode(hash),
  ].join("$");
}

export interface OAuthClientSeed {
  client_id: string;
  client_secret_hash: string;
  tenant_id: string;
  allowed_audiences: string[];
  allowed_scopes: string[];
  revoked_at: string | null;
}

export function buildSeedClients(): OAuthClientSeed[] {
  return [
    {
      client_id: TEST_OAUTH_CLIENT_ID,
      client_secret_hash: hashClientSecretSync(TEST_OAUTH_CLIENT_SECRET),
      tenant_id: TEST_TENANT_ID,
      allowed_audiences: ["bsgateway", "bsage", "bsnexus", "bsupervisor"],
      allowed_scopes: [
        "bsgateway:models:read",
        "bsgateway:models:write",
        "bsgateway:routing:read",
        "bsgateway:tenants:read",
        "bsage:notes:read",
      ],
      revoked_at: null,
    },
    {
      client_id: TEST_DEVICE_CLIENT_ID,
      // Device flow client also needs a secret for the /api/oauth/token grant
      // exchange path (which goes through Basic auth → handler → claim).
      // We don't actually use it on the device flow, but the lookup must
      // return a usable row.
      client_secret_hash: hashClientSecretSync("unused-device-secret"),
      tenant_id: TEST_TENANT_ID,
      allowed_audiences: ["bsgateway"],
      allowed_scopes: ["bsgateway:models:read"],
      revoked_at: null,
    },
  ];
}

export interface UserBearerMap {
  [accessToken: string]: { id: string };
}

export function buildSeedUsers(): UserBearerMap {
  return {
    [TEST_USER_ACCESS_TOKEN]: { id: TEST_USER_ID },
  };
}

export interface TenantMemberSeed {
  user_id: string;
  tenant_id: string;
  role: "owner" | "admin" | "member" | "viewer";
}

export function buildSeedMembers(): TenantMemberSeed[] {
  return [
    {
      user_id: TEST_USER_ID,
      tenant_id: TEST_TENANT_ID,
      role: "owner",
    },
  ];
}
