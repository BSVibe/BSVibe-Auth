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
    value: "bsgateway:models:read",
    label: "bsgateway:models:read",
    description: "List and inspect routed model deployments.",
  },
  {
    value: "bsgateway:models:write",
    label: "bsgateway:models:write",
    description: "Create, update, or remove model deployments.",
  },
  {
    value: "bsgateway:routing:read",
    label: "bsgateway:routing:read",
    description: "Read routing rules and traffic policies.",
  },
  {
    value: "bsgateway:routing:write",
    label: "bsgateway:routing:write",
    description: "Modify routing rules and traffic policies.",
  },
  {
    value: "bsgateway:tenants:read",
    label: "bsgateway:tenants:read",
    description: "Read tenant configuration.",
  },
  {
    value: "bsgateway:tenants:write",
    label: "bsgateway:tenants:write",
    description: "Modify tenant configuration.",
  },
  {
    value: "bsgateway:audit:read",
    label: "bsgateway:audit:read",
    description: "Read audit events.",
  },
  {
    value: "bsgateway:*",
    label: "bsgateway:*",
    description: "Full access to the BSGateway control plane.",
  },
  {
    value: "bsage:notes:read",
    label: "bsage:notes:read",
    description: "Read BSage notes and graph data.",
  },
  {
    value: "bsage:notes:write",
    label: "bsage:notes:write",
    description: "Create or modify BSage notes.",
  },
  {
    value: "bsage:*",
    label: "bsage:*",
    description: "Full access to BSage.",
  },
] as const;

export const AUDIENCE_CATALOG: readonly AudienceOption[] = [
  {
    value: "bsgateway",
    label: "BSGateway",
    description: "AI bsgateway / control plane.",
  },
  {
    value: "bsage",
    label: "BSage",
    description: "Knowledge graph + notes service.",
  },
  {
    value: "bsnexus",
    label: "BSVibe Nexus",
    description: "Workspace shell.",
  },
  {
    value: "bsupervisor",
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
