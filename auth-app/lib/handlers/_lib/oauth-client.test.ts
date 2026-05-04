import { describe, it, expect, vi } from "vitest";
import {
  hashClientSecret,
  verifyClientSecret,
  parseBasicAuthHeader,
  parseClientCredentials,
  fetchOAuthClient,
  type OAuthClientRecord,
} from "./oauth-client";

describe("hashClientSecret / verifyClientSecret", () => {
  it("round-trips a plain secret through PBKDF2 hash", async () => {
    const plain = "super-secret-32-bytes-of-entropy!";
    const hash = await hashClientSecret(plain);
    expect(hash).toMatch(/^pbkdf2-sha256\$\d+\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
    await expect(verifyClientSecret(plain, hash)).resolves.toBe(true);
  });

  it("rejects the wrong plaintext", async () => {
    const hash = await hashClientSecret("right-secret");
    await expect(verifyClientSecret("wrong-secret", hash)).resolves.toBe(false);
  });

  it("rejects malformed hash strings", async () => {
    await expect(verifyClientSecret("x", "not-a-hash")).resolves.toBe(false);
    await expect(verifyClientSecret("x", "sha256$1$a$b")).resolves.toBe(false);
  });

  it("uses a fresh salt on each call", async () => {
    const a = await hashClientSecret("same");
    const b = await hashClientSecret("same");
    expect(a).not.toBe(b);
    await expect(verifyClientSecret("same", a)).resolves.toBe(true);
    await expect(verifyClientSecret("same", b)).resolves.toBe(true);
  });
});

describe("parseBasicAuthHeader", () => {
  it("decodes a valid Basic header", () => {
    const header = "Basic " + Buffer.from("client:secret-x").toString("base64");
    expect(parseBasicAuthHeader(header)).toEqual({
      clientId: "client",
      clientSecret: "secret-x",
    });
  });

  it("returns null for non-Basic schemes", () => {
    expect(parseBasicAuthHeader("Bearer abc")).toBeNull();
    expect(parseBasicAuthHeader("")).toBeNull();
    expect(parseBasicAuthHeader(undefined)).toBeNull();
  });

  it("returns null when payload has no colon", () => {
    const header = "Basic " + Buffer.from("nocolonhere").toString("base64");
    expect(parseBasicAuthHeader(header)).toBeNull();
  });

  it("preserves colons inside the secret", () => {
    const header =
      "Basic " + Buffer.from("client:has:colon:in:secret").toString("base64");
    expect(parseBasicAuthHeader(header)).toEqual({
      clientId: "client",
      clientSecret: "has:colon:in:secret",
    });
  });
});

describe("parseClientCredentials", () => {
  it("prefers Authorization header over body", () => {
    const header = "Basic " + Buffer.from("hdr:hdr-secret").toString("base64");
    const result = parseClientCredentials(header, {
      client_id: "body",
      client_secret: "body-secret",
    });
    expect(result).toEqual({ clientId: "hdr", clientSecret: "hdr-secret" });
  });

  it("falls back to body credentials when header absent", () => {
    expect(
      parseClientCredentials(undefined, {
        client_id: "body",
        client_secret: "body-secret",
      }),
    ).toEqual({ clientId: "body", clientSecret: "body-secret" });
  });

  it("returns null when neither is provided", () => {
    expect(parseClientCredentials(undefined, {})).toBeNull();
    expect(parseClientCredentials(undefined, { client_id: "no-secret" })).toBeNull();
  });
});

describe("fetchOAuthClient", () => {
  const cfg = { url: "https://test.supabase.co", serviceRoleKey: "srv-key" };

  it("returns null when no row matches", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response("[]", { status: 200, headers: { "content-type": "application/json" } }),
    );
    const result = await fetchOAuthClient(cfg, "missing", fetchImpl);
    expect(result).toBeNull();
    expect(fetchImpl).toHaveBeenCalledOnce();
    const url = fetchImpl.mock.calls[0][0] as string;
    expect(url).toContain("/rest/v1/oauth_clients");
    expect(url).toContain("client_id=eq.missing");
  });

  it("returns a typed record when a row is found", async () => {
    const row: OAuthClientRecord = {
      client_id: "bsgateway-prod",
      client_secret_hash: "pbkdf2-sha256$100$AAA$BBB",
      tenant_id: "11111111-1111-4111-8111-111111111111",
      allowed_audiences: ["bsupervisor"],
      allowed_scopes: ["bsupervisor.audit.write"],
      revoked_at: null,
    };
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([row]), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const result = await fetchOAuthClient(cfg, "bsgateway-prod", fetchImpl);
    expect(result).toEqual(row);
  });

  it("throws on non-2xx Supabase response", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response("denied", { status: 500 }),
    );
    await expect(fetchOAuthClient(cfg, "anything", fetchImpl)).rejects.toThrow();
  });

  it("escapes the client_id in the URL filter", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response("[]", { status: 200 }),
    );
    await fetchOAuthClient(cfg, "weird id&plus", fetchImpl);
    const url = fetchImpl.mock.calls[0][0] as string;
    expect(url).toContain("client_id=eq.");
    expect(url).not.toContain("&plus=");
  });
});
