/**
 * Tenant data access helpers.
 *
 * Phase 0 P0.2: tenants + tenant_members live in the BSVibe-Auth Supabase
 * project. This module wraps the Supabase REST API so that handlers can list
 * a user's tenants and validate membership without pulling in a full
 * Supabase client dependency.
 *
 * No data migration is performed (decision #5 — no users yet).
 */

export type TenantRole = "owner" | "admin" | "member" | "viewer";
export type TenantPlan = "free" | "pro" | "team" | "enterprise";
export type TenantType = "personal" | "org";

export interface Tenant {
  id: string;
  name: string;
  type: TenantType;
  role: TenantRole;
  plan: TenantPlan;
}

export interface SupabaseConfig {
  url: string;
  serviceRoleKey: string;
}

export interface MembershipRow {
  tenant_id: string;
  role: TenantRole;
  tenants: {
    id: string;
    name: string;
    type: TenantType;
    plan: TenantPlan;
  } | null;
}

/**
 * Fetch all tenants the user is a member of.
 *
 * Uses Supabase service role to read across RLS — handlers must enforce
 * authentication separately.
 */
export async function listTenantsForUser(
  cfg: SupabaseConfig,
  userId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<Tenant[]> {
  const url = new URL(`${cfg.url}/rest/v1/tenant_members`);
  url.searchParams.set(
    "select",
    "tenant_id,role,tenants(id,name,type,plan)",
  );
  url.searchParams.set("user_id", `eq.${userId}`);
  // active tenants only — soft-deleted ones (deleted_at) are filtered server-side.
  url.searchParams.set("tenants.deleted_at", "is.null");

  const resp = await fetchImpl(url.toString(), {
    headers: {
      apikey: cfg.serviceRoleKey,
      Authorization: `Bearer ${cfg.serviceRoleKey}`,
      Accept: "application/json",
    },
  });

  if (!resp.ok) {
    throw new Error(`tenants_fetch_failed: ${resp.status}`);
  }

  const rows = (await resp.json()) as MembershipRow[];
  return rows
    .filter((r): r is MembershipRow & { tenants: NonNullable<MembershipRow["tenants"]> } => r.tenants !== null)
    .map((r) => ({
      id: r.tenants.id,
      name: r.tenants.name,
      type: r.tenants.type,
      role: r.role,
      plan: r.tenants.plan,
    }));
}

/**
 * Verify a user is a member of a specific tenant.
 * Returns the role if member, or null if not.
 */
export async function getMembership(
  cfg: SupabaseConfig,
  userId: string,
  tenantId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<TenantRole | null> {
  const url = new URL(`${cfg.url}/rest/v1/tenant_members`);
  url.searchParams.set("select", "role");
  url.searchParams.set("user_id", `eq.${userId}`);
  url.searchParams.set("tenant_id", `eq.${tenantId}`);

  const resp = await fetchImpl(url.toString(), {
    headers: {
      apikey: cfg.serviceRoleKey,
      Authorization: `Bearer ${cfg.serviceRoleKey}`,
      Accept: "application/json",
    },
  });

  if (!resp.ok) {
    throw new Error(`membership_fetch_failed: ${resp.status}`);
  }

  const rows = (await resp.json()) as { role: TenantRole }[];
  return rows.length > 0 ? rows[0].role : null;
}

/**
 * Determine the active tenant ID for a user.
 *
 * Priority:
 *  1. Explicit `requestedActiveTenantId` if user is a member.
 *  2. First personal tenant.
 *  3. First tenant in the list.
 *  4. null when user has no tenants.
 */
export function pickActiveTenant(
  tenants: Tenant[],
  requestedActiveTenantId?: string | null,
): string | null {
  if (tenants.length === 0) return null;
  if (requestedActiveTenantId) {
    const found = tenants.find((t) => t.id === requestedActiveTenantId);
    if (found) return found.id;
  }
  const personal = tenants.find((t) => t.type === "personal");
  if (personal) return personal.id;
  return tenants[0].id;
}
