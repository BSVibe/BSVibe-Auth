import { describe, it, expect, vi } from "vitest";
import {
  listTenantsForUser,
  getMembership,
  pickActiveTenant,
  type Tenant,
} from "./tenants";

const cfg = {
  url: "https://test.supabase.co",
  serviceRoleKey: "service-role-key",
};

describe("listTenantsForUser", () => {
  it("queries tenant_members with embedded tenants and maps the result", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [
        {
          tenant_id: "t1",
          role: "owner",
          tenants: { id: "t1", name: "Alice", type: "personal", plan: "pro" },
        },
        {
          tenant_id: "t2",
          role: "admin",
          tenants: { id: "t2", name: "ACME", type: "org", plan: "team" },
        },
      ],
    });

    const tenants = await listTenantsForUser(
      cfg,
      "user-123",
      fetchMock as unknown as typeof fetch,
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = fetchMock.mock.calls[0];
    const url = new URL(calledUrl);
    expect(url.origin + url.pathname).toBe(
      "https://test.supabase.co/rest/v1/tenant_members",
    );
    expect(url.searchParams.get("user_id")).toBe("eq.user-123");
    expect(url.searchParams.get("select")).toContain("tenants(");
    expect(calledInit.headers.apikey).toBe("service-role-key");
    expect(calledInit.headers.Authorization).toBe("Bearer service-role-key");

    expect(tenants).toEqual([
      { id: "t1", name: "Alice", type: "personal", role: "owner", plan: "pro" },
      { id: "t2", name: "ACME", type: "org", role: "admin", plan: "team" },
    ]);
  });

  it("filters out rows where tenants is null (soft-deleted)", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [
        { tenant_id: "t1", role: "owner", tenants: null },
        {
          tenant_id: "t2",
          role: "admin",
          tenants: { id: "t2", name: "ACME", type: "org", plan: "team" },
        },
      ],
    });

    const tenants = await listTenantsForUser(
      cfg,
      "u",
      fetchMock as unknown as typeof fetch,
    );
    expect(tenants).toHaveLength(1);
    expect(tenants[0].id).toBe("t2");
  });

  it("throws when supabase returns non-ok", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 500, json: async () => ({}) });
    await expect(
      listTenantsForUser(cfg, "u", fetchMock as unknown as typeof fetch),
    ).rejects.toThrow(/tenants_fetch_failed: 500/);
  });
});

describe("getMembership", () => {
  it("returns the role when membership row exists", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [{ role: "admin" }],
    });

    const role = await getMembership(
      cfg,
      "user-123",
      "tenant-456",
      fetchMock as unknown as typeof fetch,
    );

    expect(role).toBe("admin");
    const [calledUrl] = fetchMock.mock.calls[0];
    const url = new URL(calledUrl);
    expect(url.searchParams.get("user_id")).toBe("eq.user-123");
    expect(url.searchParams.get("tenant_id")).toBe("eq.tenant-456");
  });

  it("returns null when no membership", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: true, json: async () => [] });
    const role = await getMembership(
      cfg,
      "u",
      "t",
      fetchMock as unknown as typeof fetch,
    );
    expect(role).toBeNull();
  });

  it("throws when supabase returns non-ok", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 503, json: async () => ({}) });
    await expect(
      getMembership(cfg, "u", "t", fetchMock as unknown as typeof fetch),
    ).rejects.toThrow(/membership_fetch_failed: 503/);
  });
});

describe("pickActiveTenant", () => {
  const personal: Tenant = {
    id: "p",
    name: "Alice",
    type: "personal",
    role: "owner",
    plan: "pro",
  };
  const orgA: Tenant = {
    id: "a",
    name: "ACME",
    type: "org",
    role: "admin",
    plan: "team",
  };
  const orgB: Tenant = {
    id: "b",
    name: "Beta",
    type: "org",
    role: "member",
    plan: "free",
  };

  it("returns null when no tenants", () => {
    expect(pickActiveTenant([])).toBeNull();
  });

  it("respects explicit requested tenant when user is a member", () => {
    expect(pickActiveTenant([personal, orgA, orgB], "a")).toBe("a");
  });

  it("falls back to personal tenant when requested id is not a member", () => {
    expect(pickActiveTenant([personal, orgA], "unknown")).toBe("p");
  });

  it("falls back to personal tenant when no requested id", () => {
    expect(pickActiveTenant([orgA, personal])).toBe("p");
  });

  it("falls back to first tenant when no personal tenant", () => {
    expect(pickActiveTenant([orgA, orgB])).toBe("a");
  });
});
