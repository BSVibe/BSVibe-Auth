/**
 * POST /api/oauth/device/verify — user-side approval/denial of a `user_code`.
 *
 * The user (authenticated via Supabase Bearer token) confirms or rejects the
 * device-flow request matching `user_code`. Only `pending` rows that have not
 * yet expired transition state — replays / unknown codes return 404.
 *
 * On approve we also stamp the row's `user_id` so that the eventual token
 * mint (TASK-006 grant=device_code) can resolve the principal.
 */

import type { VercelRequest, VercelResponse } from "../../_lib/types";
import {
  authenticate,
  verifySupabaseAccessToken,
  type VerifyAccessTokenFn,
} from "../../api-tokens/_auth";

export interface DeviceVerifyHandlerDeps {
  verifyAccessToken?: VerifyAccessTokenFn;
  fetchImpl?: typeof fetch;
}

interface ParsedBody {
  user_code?: string;
  action?: string;
}

const USER_CODE_PATTERN = /^[A-Z0-9]{4}-[A-Z0-9]{4}$/;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function readBody(req: VercelRequest): ParsedBody {
  const raw = req.body;
  if (typeof raw === "string") {
    const ct = (req.headers["content-type"] ?? "").toLowerCase();
    if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(raw);
      return {
        user_code: params.get("user_code") ?? undefined,
        action: params.get("action") ?? undefined,
      };
    }
    try {
      const j = JSON.parse(raw) as Record<string, unknown>;
      return {
        user_code: typeof j.user_code === "string" ? j.user_code : undefined,
        action: typeof j.action === "string" ? j.action : undefined,
      };
    } catch {
      return {};
    }
  }
  if (isPlainObject(raw)) {
    return {
      user_code: typeof raw.user_code === "string" ? raw.user_code : undefined,
      action: typeof raw.action === "string" ? raw.action : undefined,
    };
  }
  return {};
}

export function createDeviceVerifyHandler(deps: DeviceVerifyHandlerDeps = {}) {
  const verifyAccessToken = deps.verifyAccessToken ?? verifySupabaseAccessToken;
  const fetchImpl = deps.fetchImpl ?? fetch;

  return async function handler(req: VercelRequest, res: VercelResponse) {
    if (req.method === "OPTIONS") {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
      res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization",
      );
      return res.status(204).end();
    }
    if (req.method !== "POST") {
      return res.status(405).json({ error: "Method not allowed" });
    }

    const auth = await authenticate(req, res, verifyAccessToken, fetchImpl);
    if (!auth) return;
    const { userId, env } = auth;

    const body = readBody(req);
    if (!body.user_code || !USER_CODE_PATTERN.test(body.user_code)) {
      return res.status(400).json({ error: "user_code is required" });
    }
    if (body.action !== "approve" && body.action !== "deny") {
      return res
        .status(400)
        .json({ error: "action must be 'approve' or 'deny'" });
    }

    const userCode = body.user_code;
    const newStatus = body.action === "approve" ? "approved" : "denied";
    const nowIso = new Date().toISOString();

    // Atomic transition: only pending + non-expired rows move forward.
    const url = new URL(`${env.supabaseUrl}/rest/v1/device_codes`);
    url.searchParams.set("user_code", `eq.${userCode}`);
    url.searchParams.set("status", "eq.pending");
    url.searchParams.set("expires_at", `gt.${nowIso}`);

    const patchBody: Record<string, unknown> = { status: newStatus };
    if (body.action === "approve") patchBody.user_id = userId;

    const resp = await fetchImpl(url.toString(), {
      method: "PATCH",
      headers: {
        apikey: env.serviceRoleKey,
        Authorization: `Bearer ${env.serviceRoleKey}`,
        "Content-Type": "application/json",
        Prefer: "return=representation",
      },
      body: JSON.stringify(patchBody),
    });
    if (!resp.ok) {
      return res
        .status(502)
        .json({ error: "Device verify failed", upstream_status: resp.status });
    }
    const rows = (await resp.json()) as unknown[];
    if (!Array.isArray(rows) || rows.length === 0) {
      return res
        .status(404)
        .json({ error: "user_code not found, expired, or already verified" });
    }

    return res.status(200).json({ status: newStatus });
  };
}

const defaultHandler = createDeviceVerifyHandler();
export default defaultHandler;
