export interface BSVibeAuthConfig {
  /** URL of the BSVibe auth app, e.g. 'https://auth.bsvibe.dev' */
  authUrl: string;
  /** Callback path on the client app. Default: '/auth/callback' */
  callbackPath?: string;
}

/**
 * Legacy session-cached user shape produced by parseToken().
 * Kept for backward compatibility with `BSVibeAuth` (token-in-localStorage flow).
 * The new `useAuth()` hook uses `User` + `Tenant` (richer, multi-tenant) instead.
 */
export interface BSVibeUser {
  id: string;
  email: string;
  tenantId: string;
  role: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

/* ---------------------------------------------------------------------------
 * Phase 0 P0.6 — multi-tenant session shape
 *
 * Mirrors the `/api/session` envelope added in PR #3 (P0.2):
 *   {
 *     user: { id, email, name?, avatar_url? },
 *     tenants: Tenant[],
 *     active_tenant_id: string | null,
 *     access_token, refresh_token, expires_in,
 *   }
 *
 * Auth_Design.md §5.1.
 * --------------------------------------------------------------------------- */

export type TenantRole = 'owner' | 'admin' | 'member' | 'viewer';
export type TenantPlan = 'free' | 'pro' | 'team' | 'enterprise';
export type TenantType = 'personal' | 'org';

export interface Tenant {
  id: string;
  name: string;
  type: TenantType;
  role: TenantRole;
  plan: TenantPlan;
}

export interface User {
  id: string;
  email: string;
  name?: string;
  avatar_url?: string;
}

/**
 * Permission identifier in `<product>.<resource>.<action>` format.
 * E.g. `bsage.note.read`, `nexus.project.write`, `core.tenant.manage`.
 *
 * The client-side helper does a coarse role × plan check for UX gating only;
 * the server (OpenFGA) is always authoritative. See Auth_Design.md §2.5.
 */
export type Permission = string;

/** Response envelope from `GET /api/session`. */
export interface SessionEnvelope {
  user: User;
  tenants: Tenant[];
  active_tenant_id: string | null;
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

/** Response from `POST /api/session/switch_tenant`. */
export interface SwitchTenantResponse {
  active_tenant_id: string;
  role: TenantRole;
}
