import { describe, it, expect } from "vitest";
import {
  generateOpaqueToken,
  generatePatJwt,
  generateRefreshToken,
  sha256Bytes,
  bytesToHex,
  hexToBytes,
  verifyPatJwtSignature,
  decodePatJwtPayload,
  type PatJwtPayload,
} from "./api-token";

const SIGNING_SECRET = "test-pat-signing-secret-32-bytes!!";
const ISSUER = "https://auth.bsvibe.dev";

const BASE62 = /^[0-9A-Za-z]+$/;
const URLSAFE_B64 = /^[0-9A-Za-z_-]+$/;

describe("sha256Bytes", () => {
  it("is deterministic for the same input", async () => {
    const a = await sha256Bytes("hello");
    const b = await sha256Bytes("hello");
    expect(a).toEqual(b);
  });

  it("differs for different inputs", async () => {
    const a = await sha256Bytes("hello");
    const b = await sha256Bytes("world");
    expect(a).not.toEqual(b);
  });

  it("returns 32 bytes", async () => {
    const out = await sha256Bytes("anything");
    expect(out.byteLength).toBe(32);
  });
});

describe("bytesToHex / hexToBytes", () => {
  it("round-trips", () => {
    const bytes = new Uint8Array([0, 1, 2, 15, 16, 254, 255]);
    const hex = bytesToHex(bytes);
    expect(hex).toBe("0001020f10feff");
    expect(hexToBytes(hex)).toEqual(bytes);
  });

  it("rejects odd-length hex", () => {
    expect(() => hexToBytes("abc")).toThrow();
  });
});

describe("generateOpaqueToken", () => {
  it("starts with the requested prefix", async () => {
    const sk = await generateOpaqueToken("bsv_sk_");
    const pk = await generateOpaqueToken("bsv_pk_");
    expect(sk.raw.startsWith("bsv_sk_")).toBe(true);
    expect(pk.raw.startsWith("bsv_pk_")).toBe(true);
  });

  it("returns prefix as the first 12 characters of raw", async () => {
    const t = await generateOpaqueToken("bsv_sk_");
    expect(t.prefix).toBe(t.raw.slice(0, 12));
    expect(t.prefix.length).toBe(12);
  });

  it("uses base62 alphabet for the random suffix", async () => {
    const t = await generateOpaqueToken("bsv_sk_");
    const suffix = t.raw.slice("bsv_sk_".length);
    expect(suffix.length).toBeGreaterThan(20);
    expect(BASE62.test(suffix)).toBe(true);
  });

  it("returns a sha256 hash of the raw token", async () => {
    const t = await generateOpaqueToken("bsv_pk_");
    const expected = await sha256Bytes(t.raw);
    expect(t.hash).toEqual(expected);
    expect(t.hash.byteLength).toBe(32);
  });

  it("produces unique tokens across 1000 calls", async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      const t = await generateOpaqueToken("bsv_sk_");
      seen.add(t.raw);
    }
    expect(seen.size).toBe(1000);
  });
});

describe("generateRefreshToken", () => {
  it("produces urlsafe base64 string with sha256 hash", async () => {
    const t = await generateRefreshToken();
    expect(t.raw.length).toBeGreaterThan(20);
    expect(URLSAFE_B64.test(t.raw)).toBe(true);
    const expected = await sha256Bytes(t.raw);
    expect(t.hash).toEqual(expected);
    expect(t.hash.byteLength).toBe(32);
  });

  it("is unique across 1000 calls", async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      seen.add((await generateRefreshToken()).raw);
    }
    expect(seen.size).toBe(1000);
  });
});

describe("generatePatJwt", () => {
  const now = 1_700_000_000;
  const payload = {
    sub: "user-123",
    tenant: "tenant-abc",
    aud: ["bsgateway", "bsage"],
    scope: ["bsgateway:models:read"],
    jti: "11111111-1111-1111-1111-111111111111",
    exp: now + 3600,
    iat: now,
  };

  it("emits a 3-part JWT with HS256 header", async () => {
    const jwt = await generatePatJwt(payload, {
      signingSecret: SIGNING_SECRET,
      issuer: ISSUER,
    });
    const parts = jwt.split(".");
    expect(parts.length).toBe(3);
    const headerJson = JSON.parse(
      atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")),
    );
    expect(headerJson).toEqual({ alg: "HS256", typ: "JWT" });
  });

  it("encodes claims and verifies with the same secret", async () => {
    const jwt = await generatePatJwt(payload, {
      signingSecret: SIGNING_SECRET,
      issuer: ISSUER,
    });
    expect(await verifyPatJwtSignature(jwt, SIGNING_SECRET)).toBe(true);
    expect(await verifyPatJwtSignature(jwt, "wrong-secret")).toBe(false);

    const decoded = decodePatJwtPayload<PatJwtPayload>(jwt);
    expect(decoded.iss).toBe(ISSUER);
    expect(decoded.sub).toBe(payload.sub);
    expect(decoded.tenant).toBe(payload.tenant);
    expect(decoded.aud).toEqual(payload.aud);
    expect(decoded.scope).toEqual(payload.scope);
    expect(decoded.jti).toBe(payload.jti);
    expect(decoded.exp).toBe(payload.exp);
    expect(decoded.iat).toBe(payload.iat);
    expect(decoded.token_type).toBe("pat");
  });

  it("requires a non-empty signing secret", async () => {
    await expect(
      generatePatJwt(payload, { signingSecret: "", issuer: ISSUER }),
    ).rejects.toThrow(/signing/i);
  });

  it("omits exp claim when input.exp is undefined (never-expiring PAT)", async () => {
    const { exp, ...noExpPayload } = payload;
    void exp;
    const jwt = await generatePatJwt(noExpPayload, {
      signingSecret: SIGNING_SECRET,
      issuer: ISSUER,
    });
    expect(await verifyPatJwtSignature(jwt, SIGNING_SECRET)).toBe(true);
    const decoded = decodePatJwtPayload<PatJwtPayload & { exp?: number }>(jwt);
    expect(decoded.exp).toBeUndefined();
    expect("exp" in decoded).toBe(false);
    expect(decoded.token_type).toBe("pat");
    expect(decoded.iat).toBe(payload.iat);
  });
});
