/**
 * Static catalog of scopes and audiences used by the dashboard token-create
 * UI. Centralized here so the picker and any future server-side validation
 * can share the same source of truth without round-tripping the DB.
 */

export interface ScopeOption {
  value: string;
  label: string;
  description: string;
}

export interface AudienceOption {
  value: string;
  label: string;
  description: string;
}

export const SCOPE_CATALOG: readonly ScopeOption[] = [
  {
    value: "gateway:models:read",
    label: "gateway:models:read",
    description: "List and inspect routed model deployments.",
  },
  {
    value: "gateway:models:write",
    label: "gateway:models:write",
    description: "Create, update, or remove model deployments.",
  },
  {
    value: "gateway:routing:read",
    label: "gateway:routing:read",
    description: "Read routing rules and traffic policies.",
  },
  {
    value: "gateway:routing:write",
    label: "gateway:routing:write",
    description: "Modify routing rules and traffic policies.",
  },
  {
    value: "gateway:tenants:read",
    label: "gateway:tenants:read",
    description: "Read tenant configuration.",
  },
  {
    value: "gateway:tenants:write",
    label: "gateway:tenants:write",
    description: "Modify tenant configuration.",
  },
  {
    value: "gateway:audit:read",
    label: "gateway:audit:read",
    description: "Read audit events.",
  },
  {
    value: "gateway:*",
    label: "gateway:*",
    description: "Full access to the BSGateway control plane.",
  },
  {
    value: "sage:notes:read",
    label: "sage:notes:read",
    description: "Read BSage notes and graph data.",
  },
  {
    value: "sage:notes:write",
    label: "sage:notes:write",
    description: "Create or modify BSage notes.",
  },
  {
    value: "sage:*",
    label: "sage:*",
    description: "Full access to BSage.",
  },
] as const;

export const AUDIENCE_CATALOG: readonly AudienceOption[] = [
  {
    value: "gateway",
    label: "BSGateway",
    description: "AI gateway / control plane.",
  },
  {
    value: "sage",
    label: "BSage",
    description: "Knowledge graph + notes service.",
  },
  {
    value: "nexus",
    label: "BSVibe Nexus",
    description: "Workspace shell.",
  },
  {
    value: "supervisor",
    label: "BSVibe Supervisor",
    description: "Cross-product orchestration agent.",
  },
] as const;

export interface ExpiryOption {
  value: number;
  label: string;
}

/**
 * TTL options. Values are seconds. `value: 0` is reserved for the "default"
 * choice — backend chooses based on token type (1h for PAT, 90d for api_key).
 */
export const EXPIRY_CATALOG: readonly ExpiryOption[] = [
  { value: 0, label: "Default (1h PAT / 90d API key)" },
  { value: 3600, label: "1 hour" },
  { value: 24 * 3600, label: "1 day" },
  { value: 7 * 24 * 3600, label: "7 days" },
  { value: 30 * 24 * 3600, label: "30 days" },
  { value: 90 * 24 * 3600, label: "90 days" },
  { value: 365 * 24 * 3600, label: "1 year" },
] as const;
