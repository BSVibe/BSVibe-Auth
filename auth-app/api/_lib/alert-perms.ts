/**
 * Alert routing permission helpers.
 *
 * D18 (BSVibe_Audit_Design.md §11 D-Z2) introduces ``core.alerts.read`` and
 * ``core.alerts.manage`` for the alert_routes table. Phase 0 P0.4
 * (`bsvibe-authz`) will wire these into a single
 * ``public.has_permission(uid, tenant_id, perm)`` Supabase function. Until
 * that lands, the contract is enforced via tenant_members.role:
 *
 *   - core.alerts.read   ⇒ owner | admin
 *   - core.alerts.manage ⇒ owner | admin
 *
 * Splitting them now (even though they currently overlap) means the swap to
 * fine-grained authz is a single-file change.
 */
import type { SupabaseConfig, TenantRole } from "./tenants";
import { getMembership } from "./tenants";

export type AlertPermission =
  | "core.alerts.read"
  | "core.alerts.manage";

export type HasAlertPermissionFn = (
  cfg: SupabaseConfig,
  userId: string,
  tenantId: string,
  permission: AlertPermission,
  fetchImpl?: typeof fetch,
) => Promise<boolean>;

const ALERT_PERMISSION_ROLES: Record<AlertPermission, ReadonlySet<TenantRole>> = {
  "core.alerts.read": new Set<TenantRole>(["owner", "admin"]),
  "core.alerts.manage": new Set<TenantRole>(["owner", "admin"]),
};

export async function defaultHasAlertPermission(
  cfg: SupabaseConfig,
  userId: string,
  tenantId: string,
  permission: AlertPermission,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  const allowed = ALERT_PERMISSION_ROLES[permission];
  if (!allowed) return false;
  const role = await getMembership(cfg, userId, tenantId, fetchImpl);
  if (!role) return false;
  return allowed.has(role);
}
