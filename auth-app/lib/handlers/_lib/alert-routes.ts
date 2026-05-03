/**
 * alert_routes CRUD against Supabase PostgREST.
 *
 * Service-role client: bypasses RLS. Handlers MUST authorise the caller
 * before invoking these helpers.
 */
import type { SupabaseConfig } from "./tenants";

export type AlertSeverity = "info" | "warning" | "critical";
export type AlertChannel = "telegram" | "slack" | "structlog";

export interface AlertRoute {
  id: string;
  tenant_id: string;
  name: string;
  event_pattern: string;
  severity: AlertSeverity;
  channel: AlertChannel;
  config: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AlertRouteInput {
  name: string;
  event_pattern: string;
  severity: AlertSeverity;
  channel: AlertChannel;
  config?: Record<string, unknown>;
  enabled?: boolean;
}

export type AlertRoutePatch = Partial<AlertRouteInput>;

const SELECT_COLS =
  "id,tenant_id,name,event_pattern,severity,channel,config,enabled,created_at,updated_at";

export async function listAlertRoutes(
  cfg: SupabaseConfig,
  tenantId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<AlertRoute[]> {
  const url = new URL(`${cfg.url}/rest/v1/alert_routes`);
  url.searchParams.set("select", SELECT_COLS);
  url.searchParams.set("tenant_id", `eq.${tenantId}`);
  url.searchParams.set("order", "created_at.desc");

  const resp = await fetchImpl(url.toString(), {
    headers: {
      apikey: cfg.serviceRoleKey,
      Authorization: `Bearer ${cfg.serviceRoleKey}`,
      Accept: "application/json",
    },
  });
  if (!resp.ok) throw new Error(`alert_routes_list_failed: ${resp.status}`);
  return (await resp.json()) as AlertRoute[];
}

export async function listEnabledAlertRoutes(
  cfg: SupabaseConfig,
  tenantId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<AlertRoute[]> {
  const url = new URL(`${cfg.url}/rest/v1/alert_routes`);
  url.searchParams.set("select", SELECT_COLS);
  url.searchParams.set("tenant_id", `eq.${tenantId}`);
  url.searchParams.set("enabled", "eq.true");
  url.searchParams.set("order", "created_at.desc");

  const resp = await fetchImpl(url.toString(), {
    headers: {
      apikey: cfg.serviceRoleKey,
      Authorization: `Bearer ${cfg.serviceRoleKey}`,
      Accept: "application/json",
    },
  });
  if (!resp.ok) throw new Error(`alert_routes_list_failed: ${resp.status}`);
  return (await resp.json()) as AlertRoute[];
}

export async function insertAlertRoute(
  cfg: SupabaseConfig,
  tenantId: string,
  input: AlertRouteInput,
  fetchImpl: typeof fetch = fetch,
): Promise<AlertRoute> {
  const row = {
    tenant_id: tenantId,
    name: input.name,
    event_pattern: input.event_pattern,
    severity: input.severity,
    channel: input.channel,
    config: input.config ?? {},
    enabled: input.enabled ?? true,
  };
  const resp = await fetchImpl(`${cfg.url}/rest/v1/alert_routes`, {
    method: "POST",
    headers: {
      apikey: cfg.serviceRoleKey,
      Authorization: `Bearer ${cfg.serviceRoleKey}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
    },
    body: JSON.stringify(row),
  });
  if (!resp.ok) throw new Error(`alert_route_insert_failed: ${resp.status}`);
  const rows = (await resp.json()) as AlertRoute[];
  if (!Array.isArray(rows) || rows.length === 0) {
    throw new Error("alert_route_insert_empty");
  }
  return rows[0];
}

export async function updateAlertRoute(
  cfg: SupabaseConfig,
  tenantId: string,
  routeId: string,
  patch: AlertRoutePatch,
  fetchImpl: typeof fetch = fetch,
): Promise<AlertRoute | null> {
  const url = new URL(`${cfg.url}/rest/v1/alert_routes`);
  url.searchParams.set("id", `eq.${routeId}`);
  url.searchParams.set("tenant_id", `eq.${tenantId}`);

  // Strip undefined keys so PATCH does not blank columns.
  const body: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(patch)) {
    if (v !== undefined) body[k] = v;
  }
  if (Object.keys(body).length === 0) {
    throw new Error("alert_route_patch_empty");
  }

  const resp = await fetchImpl(url.toString(), {
    method: "PATCH",
    headers: {
      apikey: cfg.serviceRoleKey,
      Authorization: `Bearer ${cfg.serviceRoleKey}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(`alert_route_update_failed: ${resp.status}`);
  const rows = (await resp.json()) as AlertRoute[];
  return rows.length > 0 ? rows[0] : null;
}

export async function deleteAlertRoute(
  cfg: SupabaseConfig,
  tenantId: string,
  routeId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  const url = new URL(`${cfg.url}/rest/v1/alert_routes`);
  url.searchParams.set("id", `eq.${routeId}`);
  url.searchParams.set("tenant_id", `eq.${tenantId}`);

  const resp = await fetchImpl(url.toString(), {
    method: "DELETE",
    headers: {
      apikey: cfg.serviceRoleKey,
      Authorization: `Bearer ${cfg.serviceRoleKey}`,
      Prefer: "return=representation",
    },
  });
  if (!resp.ok) throw new Error(`alert_route_delete_failed: ${resp.status}`);
  const rows = (await resp.json()) as AlertRoute[];
  return rows.length > 0;
}
