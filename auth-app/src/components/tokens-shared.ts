/**
 * Shared types and helpers for the /dashboard/tokens UI surface.
 */

export interface TokenRow {
  id: string;
  type: 'pat' | 'api_key';
  prefix: string | null;
  name: string;
  audience: string[];
  scopes: string[];
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
}

export function formatDate(value: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}
