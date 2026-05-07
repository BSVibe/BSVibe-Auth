/**
 * Device-grant token-claim helper.
 *
 * Used by the extended /api/oauth/token grant dispatcher (TASK-006) to
 * atomically consume an approved `device_codes` row and surface the principal
 * + scope/audience to mint the resulting PAT.
 *
 * NOTE: This file is the *internal helper* `claimDeviceCode` — it is NOT the
 * `/api/oauth/token` HTTP endpoint. Don't confuse with `lib/handlers/oauth/token.ts`.
 *
 * Atomicity: a single PostgREST `PATCH` with strict filters (
 * device_code=eq + client_id=eq + status=eq.approved + expires_at=gt.now)
 * relies on row-level locking to ensure exactly one caller transitions
 * `approved → consumed`. A second concurrent claim sees `status='consumed'`
 * and matches zero rows, returning `{ kind: "consumed" }`.
 */

export interface ClaimDeviceCodeEnv {
  url: string;
  serviceRoleKey: string;
}

export interface ClaimDeviceCodeOptions {
  fetchImpl?: typeof fetch;
  now?: () => number;
}

export type ClaimDeviceCodeOutcome =
  | {
      kind: "claimed";
      userId: string;
      scope: string[];
      audience: string[];
      clientId: string;
    }
  | { kind: "pending" }
  | { kind: "denied" }
  | { kind: "expired" }
  | { kind: "consumed" }
  | { kind: "not_found" };

interface DeviceCodeRow {
  device_code: string;
  client_id: string;
  user_id: string | null;
  scope: unknown;
  audience: unknown;
  status: "pending" | "approved" | "denied" | "expired" | "consumed";
  expires_at?: string;
}

function asStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string");
}

export async function claimDeviceCode(
  env: ClaimDeviceCodeEnv,
  deviceCode: string,
  clientId: string,
  options: ClaimDeviceCodeOptions = {},
): Promise<ClaimDeviceCodeOutcome> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;
  const nowIso = new Date(now()).toISOString();

  const headers = {
    apikey: env.serviceRoleKey,
    Authorization: `Bearer ${env.serviceRoleKey}`,
    Accept: "application/json",
  } as const;

  // 1) Atomic claim: approved + non-expired + same client_id → consumed.
  const claimUrl = new URL(`${env.url}/rest/v1/device_codes`);
  claimUrl.searchParams.set("device_code", `eq.${deviceCode}`);
  claimUrl.searchParams.set("client_id", `eq.${clientId}`);
  claimUrl.searchParams.set("status", "eq.approved");
  claimUrl.searchParams.set("expires_at", `gt.${nowIso}`);

  const claimResp = await fetchImpl(claimUrl.toString(), {
    method: "PATCH",
    headers: { ...headers, "Content-Type": "application/json", Prefer: "return=representation" },
    body: JSON.stringify({ status: "consumed" }),
  });
  if (!claimResp.ok) {
    // Treat upstream errors as not-found to avoid leaking detail; the caller
    // emits `invalid_grant` either way.
    return { kind: "not_found" };
  }
  const claimed = (await claimResp.json()) as DeviceCodeRow[];
  if (Array.isArray(claimed) && claimed.length === 1) {
    const row = claimed[0];
    return {
      kind: "claimed",
      userId: row.user_id ?? "",
      scope: asStringArray(row.scope),
      audience: asStringArray(row.audience),
      clientId: row.client_id,
    };
  }

  // 2) Diagnostic lookup — same row is now in some other state.
  const lookupUrl = new URL(`${env.url}/rest/v1/device_codes`);
  lookupUrl.searchParams.set(
    "select",
    "device_code,client_id,user_id,scope,audience,status,expires_at",
  );
  lookupUrl.searchParams.set("device_code", `eq.${deviceCode}`);
  lookupUrl.searchParams.set("client_id", `eq.${clientId}`);
  lookupUrl.searchParams.set("limit", "1");

  const lookupResp = await fetchImpl(lookupUrl.toString(), { headers });
  if (!lookupResp.ok) return { kind: "not_found" };
  const rows = (await lookupResp.json()) as DeviceCodeRow[];
  if (!Array.isArray(rows) || rows.length === 0) return { kind: "not_found" };
  const row = rows[0];

  // Lazily classify expiration even when status is still 'approved' or 'pending'
  // — the periodic janitor may not have run yet.
  if (row.expires_at) {
    const expMs = Date.parse(row.expires_at);
    if (!Number.isNaN(expMs) && expMs <= now()) {
      return { kind: "expired" };
    }
  }
  switch (row.status) {
    case "pending":
      return { kind: "pending" };
    case "denied":
      return { kind: "denied" };
    case "consumed":
      return { kind: "consumed" };
    case "expired":
      return { kind: "expired" };
    default:
      // 'approved' but the atomic claim failed — race with another consumer
      // that already moved it forward. Treat as not_found so the caller emits
      // invalid_grant.
      return { kind: "not_found" };
  }
}
