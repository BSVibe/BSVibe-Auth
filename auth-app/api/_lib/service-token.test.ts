import { describe, it, expect } from "vitest";
import {
  issueServiceToken,
  decodeJwtPayload,
  verifyServiceTokenSignature,
  validateAudience,
  validateScopes,
  validateTtl,
  ServiceTokenError,
  type ServiceTokenPayload,
  SERVICE_AUDIENCES,
} from "./service-token";

const cfg = {
  signingSecret: "test-signing-secret-32-bytes-min!!",
  issuer: "https://auth.bsvibe.dev",
  now: () => 1_700_000_000_000,
};

describe("validateAudience", () => {
  it("accepts each valid audience", () => {
    for (const aud of SERVICE_AUDIENCES) {
      expect(validateAudience(aud)).toBe(aud);
    }
  });
  it("rejects unknown audience", () => {
    expect(() => validateAudience("unknown")).toThrow(ServiceTokenError);
    expect(() => validateAudience("unknown")).toThrow(/invalid_audience|one of/);
  });
  it("rejects non-string", () => {
    expect(() => validateAudience(42)).toThrow(ServiceTokenError);
    expect(() => validateAudience(null)).toThrow(ServiceTokenError);
  });
});

describe("validateScopes", () => {
  it("accepts well-formed scopes matching audience", () => {
    expect(validateScopes("bsage", ["bsage.read", "bsage.write"])).toEqual([
      "bsage.read",
      "bsage.write",
    ]);
  });
  it("sorts and dedupes scopes", () => {
    expect(validateScopes("bsage", ["bsage.write", "bsage.read", "bsage.read"])).toEqual([
      "bsage.read",
      "bsage.write",
    ]);
  });
  it("rejects empty scope list", () => {
    expect(() => validateScopes("bsage", [])).toThrow(/invalid_scope/);
  });
  it("rejects malformed scope identifier", () => {
    expect(() => validateScopes("bsage", ["BSAGE.read"])).toThrow(/invalid_scope/);
    expect(() => validateScopes("bsage", ["bsage_read"])).toThrow(/invalid_scope/);
    expect(() => validateScopes("bsage", ["bsage."])).toThrow(/invalid_scope/);
  });
  it("rejects scope whose namespace does not match audience (decision #16)", () => {
    let err: ServiceTokenError | null = null;
    try {
      validateScopes("bsage", ["bsage.read", "bsgateway.write"]);
    } catch (e) {
      err = e as ServiceTokenError;
    }
    expect(err).toBeInstanceOf(ServiceTokenError);
    expect(err?.code).toBe("scope_audience_mismatch");
  });
  it("rejects non-array", () => {
    expect(() => validateScopes("bsage", "bsage.read")).toThrow(/invalid_scope/);
  });
});

describe("validateTtl", () => {
  it("returns 3600 default when undefined", () => {
    expect(validateTtl(undefined)).toBe(3600);
    expect(validateTtl(null)).toBe(3600);
  });
  it("accepts integer in [60, 86400]", () => {
    expect(validateTtl(60)).toBe(60);
    expect(validateTtl(7200)).toBe(7200);
    expect(validateTtl(86400)).toBe(86400);
  });
  it("rejects out-of-range or non-integer", () => {
    expect(() => validateTtl(30)).toThrow(/invalid_ttl/);
    expect(() => validateTtl(86401)).toThrow(/invalid_ttl/);
    expect(() => validateTtl(60.5)).toThrow(/invalid_ttl/);
    expect(() => validateTtl("60")).toThrow(/invalid_ttl/);
  });
});

describe("issueServiceToken", () => {
  it("produces a JWT with audience, scope, iat/exp, token_type=service", async () => {
    const result = await issueServiceToken(
      {
        audience: "bsage",
        scope: ["bsage.read", "bsage.write"],
        subject: "service:bsnexus",
        ttlSeconds: 7200,
      },
      cfg,
    );

    expect(result.access_token.split(".")).toHaveLength(3);
    expect(result.expires_in).toBe(7200);

    const payload = decodeJwtPayload<ServiceTokenPayload>(result.access_token);
    expect(payload.iss).toBe("https://auth.bsvibe.dev");
    expect(payload.aud).toBe("bsage");
    expect(payload.scope).toBe("bsage.read bsage.write");
    expect(payload.sub).toBe("service:bsnexus");
    expect(payload.token_type).toBe("service");
    expect(payload.iat).toBe(Math.floor(cfg.now() / 1000));
    expect(payload.exp).toBe(payload.iat + 7200);
    expect(payload.tenant_id).toBeUndefined();
  });

  it("defaults TTL to 3600 when ttlSeconds is omitted", async () => {
    const result = await issueServiceToken(
      {
        audience: "bsupervisor",
        scope: ["bsupervisor.read"],
        subject: "user:abc",
      },
      cfg,
    );
    expect(result.expires_in).toBe(3600);
    const payload = decodeJwtPayload<ServiceTokenPayload>(result.access_token);
    expect(payload.exp - payload.iat).toBe(3600);
  });

  it("includes tenant_id claim when provided", async () => {
    const result = await issueServiceToken(
      {
        audience: "bsnexus",
        scope: ["bsnexus.read"],
        subject: "user:abc",
        tenantId: "tenant-xyz",
      },
      cfg,
    );
    const payload = decodeJwtPayload<ServiceTokenPayload>(result.access_token);
    expect(payload.tenant_id).toBe("tenant-xyz");
  });

  it("produces a verifiable HS256 signature", async () => {
    const result = await issueServiceToken(
      {
        audience: "bsgateway",
        scope: ["bsgateway.read"],
        subject: "service:bsnexus",
      },
      cfg,
    );
    expect(
      await verifyServiceTokenSignature(result.access_token, cfg.signingSecret),
    ).toBe(true);
    expect(
      await verifyServiceTokenSignature(result.access_token, "wrong-secret"),
    ).toBe(false);
  });

  it("rejects empty subject", async () => {
    await expect(
      issueServiceToken(
        {
          audience: "bsage",
          scope: ["bsage.read"],
          subject: "",
        },
        cfg,
      ),
    ).rejects.toThrow(/missing_subject/);
  });

  it("rejects when signing secret is empty", async () => {
    await expect(
      issueServiceToken(
        {
          audience: "bsage",
          scope: ["bsage.read"],
          subject: "service:bsnexus",
        },
        { ...cfg, signingSecret: "" },
      ),
    ).rejects.toThrow(/missing_secret/);
  });

  it("propagates audience mismatch validation errors", async () => {
    await expect(
      issueServiceToken(
        {
          audience: "bsage",
          scope: ["bsage.read", "bsgateway.write"],
          subject: "service:x",
        },
        cfg,
      ),
    ).rejects.toThrow(/scope_audience_mismatch|bsgateway/);
  });
});
