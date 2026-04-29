// Legacy single-tenant token-in-localStorage client.
export { BSVibeAuth } from './client';

// Phase 0 P0.6 — multi-tenant React hook + helpers.
export { AuthProvider, useAuth } from './useAuth';
export type { UseAuthValue } from './useAuth';
export { hasPermission } from './permissions';
export { switchTenant } from './switchTenant';
export type { SwitchTenantOptions } from './switchTenant';

// Public types.
export type {
  BSVibeAuthConfig,
  BSVibeUser,
  Permission,
  SessionEnvelope,
  SwitchTenantResponse,
  Tenant,
  TenantPlan,
  TenantRole,
  TenantType,
  User,
} from './types';
