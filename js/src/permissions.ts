import type { Permission, Tenant, TenantPlan, TenantRole, User } from './types';

/**
 * Client-side RBAC hint.
 *
 * Returns true if the user *probably* has the permission given their role on
 * `activeTenant` and the tenant's plan. **The server (OpenFGA) remains
 * authoritative** — this helper exists for UX gating only (hide buttons,
 * disable menu items, etc.).
 *
 * Rules (mirrors Auth_Design.md §2.3, §2.5, §2.6):
 *
 * - Permission format: `<product>.<resource>.<action>` where action ∈
 *   `read | write | create | delete | execute | manage`.
 * - Role hierarchy (higher implies lower): `owner > admin > member > viewer`.
 * - `viewer` may only read.
 * - `member` may read/write/create on free; delete requires pro+.
 * - `admin` adds member.invite (team+) on top of member; owner adds tenant.manage.
 * - `execute` always requires pro+ (feature-gated by plan).
 * - `core.tenant.manage` is owner-only regardless of plan.
 * - `core.member.invite` requires admin+ AND team+ plan.
 *
 * Anything not matching the format returns false.
 */
export function hasPermission(
  user: User | null,
  activeTenant: Tenant | null,
  permission: Permission,
): boolean {
  if (!user || !activeTenant) return false;

  const parts = permission.split('.');
  if (parts.length !== 3) return false;

  const [, resource, action] = parts;
  if (!resource || !action) return false;

  const { role, plan } = activeTenant;

  // Special-case core permissions (tenant + member management).
  if (permission === 'core.tenant.manage') {
    return role === 'owner';
  }
  if (permission === 'core.member.invite') {
    return roleAtLeast(role, 'admin') && planAtLeast(plan, 'team');
  }

  switch (action) {
    case 'read':
      return roleAtLeast(role, 'viewer');

    case 'write':
    case 'create':
      return roleAtLeast(role, 'member');

    case 'delete':
      // member can delete only on pro+; admin/owner always.
      if (roleAtLeast(role, 'admin')) return true;
      if (role === 'member') return planAtLeast(plan, 'pro');
      return false;

    case 'execute':
      // Execute is feature-gated by plan (pro+) and requires write-capable role.
      return roleAtLeast(role, 'member') && planAtLeast(plan, 'pro');

    case 'manage':
      // Generic *.manage requires owner unless explicitly handled above.
      return role === 'owner';

    default:
      return false;
  }
}

const ROLE_RANK: Record<TenantRole, number> = {
  viewer: 0,
  member: 1,
  admin: 2,
  owner: 3,
};

const PLAN_RANK: Record<TenantPlan, number> = {
  free: 0,
  pro: 1,
  team: 2,
  enterprise: 3,
};

function roleAtLeast(role: TenantRole, min: TenantRole): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[min];
}

function planAtLeast(plan: TenantPlan, min: TenantPlan): boolean {
  return PLAN_RANK[plan] >= PLAN_RANK[min];
}
