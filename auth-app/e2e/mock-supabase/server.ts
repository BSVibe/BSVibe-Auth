/**
 * Minimal in-memory PostgREST-style mock for Playwright e2e.
 *
 * Implements only what the tokens / oauth handlers in this repo actually
 * call — not full PostgREST. Filters supported on URL search params:
 *   col=eq.<v>          equality
 *   col=is.null         null check
 *   col=gt.<iso>        ISO-string greater-than (used for expires_at)
 *   limit=N             slice the result
 *   select=...,...      ignored (we always return whole rows)
 *   order=col.desc      ignored (insertion order is good enough for tests)
 *
 * Tables persisted in memory:
 *   tokens, refresh_tokens, device_codes, oauth_clients, tenant_members,
 *   audit_events
 *
 * Auth surface:
 *   GET  /auth/v1/user                       — Bearer → { id }
 *   POST /rest/v1/rpc/touch_oauth_client_last_used — no-op 200
 */

import http from "node:http";
import type { AddressInfo } from "node:net";
import {
  buildSeedClients,
  buildSeedMembers,
  buildSeedUsers,
  type OAuthClientSeed,
  type TenantMemberSeed,
  type UserBearerMap,
} from "./seed";

type Row = Record<string, unknown>;

interface Filter {
  col: string;
  op: "eq" | "is" | "gt";
  value: string;
}

function parseFilters(params: URLSearchParams): Filter[] {
  const out: Filter[] = [];
  for (const [k, v] of params.entries()) {
    if (k === "select" || k === "order" || k === "limit") continue;
    if (v.startsWith("eq.")) {
      out.push({ col: k, op: "eq", value: v.slice(3) });
    } else if (v.startsWith("is.")) {
      out.push({ col: k, op: "is", value: v.slice(3) });
    } else if (v.startsWith("gt.")) {
      out.push({ col: k, op: "gt", value: v.slice(3) });
    }
  }
  return out;
}

function applyFilters(rows: Row[], filters: Filter[]): Row[] {
  return rows.filter((row) => {
    for (const f of filters) {
      const v = row[f.col];
      if (f.op === "eq") {
        if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
          if (String(v) !== f.value) return false;
        } else {
          return false;
        }
      } else if (f.op === "is") {
        if (f.value === "null" && v !== null && v !== undefined) return false;
        if (f.value === "not.null" && (v === null || v === undefined)) return false;
      } else if (f.op === "gt") {
        if (typeof v !== "string") return false;
        if (Date.parse(v) <= Date.parse(f.value)) return false;
      }
    }
    return true;
  });
}

function applyLimit(rows: Row[], params: URLSearchParams): Row[] {
  const lim = params.get("limit");
  if (!lim) return rows;
  const n = Number.parseInt(lim, 10);
  if (!Number.isFinite(n) || n < 0) return rows;
  return rows.slice(0, n);
}

async function readJson(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const buf = Buffer.concat(chunks);
      if (buf.length === 0) {
        resolve(null);
        return;
      }
      try {
        resolve(JSON.parse(buf.toString("utf8")));
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(body));
}

function sendNoContent(res: http.ServerResponse, status = 204): void {
  res.statusCode = status;
  res.end();
}

interface MockState {
  users: UserBearerMap;
  oauth_clients: OAuthClientSeed[];
  tenant_members: TenantMemberSeed[];
  tokens: Row[];
  refresh_tokens: Row[];
  device_codes: Row[];
  audit_events: Row[];
}

function buildInitialState(): MockState {
  return {
    users: buildSeedUsers(),
    oauth_clients: buildSeedClients(),
    tenant_members: buildSeedMembers(),
    tokens: [],
    refresh_tokens: [],
    device_codes: [],
    audit_events: [],
  };
}

/**
 * Per-table nullable defaults. Real PostgreSQL returns NULL for columns the
 * caller did not specify on INSERT; the handlers do `=== null` strict checks
 * against those columns, so the mock must materialize them as null instead
 * of leaving them `undefined` after `JSON.parse`.
 */
const TABLE_DEFAULTS: Record<string, Row> = {
  tokens: {
    prefix: null,
    token_hash: null,
    jti: null,
    expires_at: null,
    last_used_at: null,
    revoked_at: null,
  },
  refresh_tokens: {
    used_at: null,
  },
  device_codes: {
    user_id: null,
  },
  oauth_clients: {
    revoked_at: null,
  },
};

function withDefaults(table: string, row: Row): Row {
  const defaults = TABLE_DEFAULTS[table];
  if (!defaults) return { ...row };
  return { ...defaults, ...row };
}

function tableFromState(state: MockState, name: string): Row[] | null {
  switch (name) {
    case "tokens":
      return state.tokens;
    case "refresh_tokens":
      return state.refresh_tokens;
    case "device_codes":
      return state.device_codes;
    case "oauth_clients":
      return state.oauth_clients as unknown as Row[];
    case "tenant_members":
      return state.tenant_members as unknown as Row[];
    case "audit_events":
      return state.audit_events;
    default:
      return null;
  }
}

function replaceTable(state: MockState, name: string, rows: Row[]): void {
  switch (name) {
    case "tokens":
      state.tokens = rows;
      return;
    case "refresh_tokens":
      state.refresh_tokens = rows;
      return;
    case "device_codes":
      state.device_codes = rows;
      return;
  }
}

export interface MockSupabase {
  url: string;
  port: number;
  reset(): void;
  state(): MockState;
  close(): Promise<void>;
}

export function startMockSupabase(port = 0): Promise<MockSupabase> {
  let state = buildInitialState();

  const handle = (req: http.IncomingMessage, res: http.ServerResponse): void => {
    void handleAsync(req, res).catch((err) => {
      console.error("[mock-supabase] handler error", err);
      sendJson(res, 500, { error: "mock_internal", detail: String(err) });
    });
  };

  async function handleAsync(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const reqUrl = new URL(req.url ?? "/", "http://127.0.0.1");
    const method = (req.method ?? "GET").toUpperCase();
    const path = reqUrl.pathname;

    // CORS / preflight — handlers don't actually need this, but be permissive.
    if (method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "*");
      sendNoContent(res, 204);
      return;
    }

    if (path === "/auth/v1/user" && method === "GET") {
      const auth = req.headers["authorization"] ?? "";
      const m = /^Bearer\s+(.+)$/i.exec(typeof auth === "string" ? auth : "");
      if (!m) {
        sendJson(res, 401, { error: "missing bearer" });
        return;
      }
      const user = state.users[m[1]];
      if (!user) {
        sendJson(res, 401, { error: "unknown bearer" });
        return;
      }
      sendJson(res, 200, { id: user.id });
      return;
    }

    if (
      path === "/rest/v1/rpc/touch_oauth_client_last_used" &&
      method === "POST"
    ) {
      sendJson(res, 200, {});
      return;
    }

    const restMatch = /^\/rest\/v1\/([a-z_]+)\/?$/.exec(path);
    if (restMatch) {
      const table = restMatch[1];
      const rows = tableFromState(state, table);
      if (!rows) {
        sendJson(res, 404, { error: `unknown table ${table}` });
        return;
      }
      const params = reqUrl.searchParams;
      const filters = parseFilters(params);
      const prefer = (req.headers["prefer"] as string | undefined) ?? "";

      if (method === "GET") {
        const matched = applyLimit(applyFilters(rows, filters), params);
        sendJson(res, 200, matched);
        return;
      }

      if (method === "POST") {
        const body = await readJson(req);
        const insert = Array.isArray(body) ? (body as Row[]) : [body as Row];
        const stored = insert.map((row) => withDefaults(table, row));
        for (const row of stored) {
          rows.push(row);
        }
        if (prefer.includes("return=minimal")) {
          sendNoContent(res, 201);
          return;
        }
        sendJson(res, 201, stored);
        return;
      }

      if (method === "PATCH") {
        const body = (await readJson(req)) as Row;
        const matched = applyFilters(rows, filters);
        for (const row of matched) {
          for (const [k, v] of Object.entries(body)) {
            row[k] = v;
          }
        }
        if (prefer.includes("return=representation")) {
          sendJson(res, 200, matched);
          return;
        }
        sendNoContent(res, 204);
        return;
      }

      if (method === "DELETE") {
        const keep: Row[] = [];
        const dropped: Row[] = [];
        for (const r of rows) {
          if (applyFilters([r], filters).length > 0) dropped.push(r);
          else keep.push(r);
        }
        replaceTable(state, table, keep);
        if (prefer.includes("return=representation")) {
          sendJson(res, 200, dropped);
          return;
        }
        sendNoContent(res, 204);
        return;
      }
    }

    sendJson(res, 404, { error: `mock route not found: ${method} ${path}` });
  }

  const server = http.createServer(handle);
  return new Promise((resolve) => {
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo;
      const actualPort = addr.port;
      const url = `http://127.0.0.1:${actualPort}`;
      resolve({
        url,
        port: actualPort,
        reset() {
          state = buildInitialState();
        },
        state() {
          return state;
        },
        close() {
          return new Promise<void>((r, j) => {
            server.close((err) => (err ? j(err) : r()));
          });
        },
      });
    });
  });
}
