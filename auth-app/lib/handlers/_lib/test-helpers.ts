/**
 * Test helpers for Vercel serverless handler unit tests.
 *
 * Provides minimal req/res shims compatible with `@vercel/node` so handlers
 * can be exercised without booting a real Vercel runtime.
 */

import type { VercelRequest, VercelResponse } from "./types";

export interface CapturedResponse {
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: unknown;
  ended: boolean;
  redirectLocation?: string;
}

export interface MockRequestInit {
  method?: string;
  headers?: Record<string, string>;
  query?: Record<string, string>;
  body?: unknown;
  cookies?: Record<string, string>;
}

export function makeReq(init: MockRequestInit = {}): VercelRequest {
  const cookieHeader = init.cookies
    ? Object.entries(init.cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join("; ")
    : undefined;

  const headers: Record<string, string> = {
    ...(init.headers ?? {}),
  };
  if (cookieHeader && !headers.cookie) {
    headers.cookie = cookieHeader;
  }

  return {
    method: init.method ?? "GET",
    headers,
    query: init.query ?? {},
    body: init.body,
    cookies: init.cookies ?? {},
  } as unknown as VercelRequest;
}

export function makeRes(): { res: VercelResponse; captured: CapturedResponse } {
  const captured: CapturedResponse = {
    statusCode: 200,
    headers: {},
    body: undefined,
    ended: false,
  };

  const res = {
    setHeader(name: string, value: string | string[]) {
      captured.headers[name] = value;
      return res;
    },
    getHeader(name: string) {
      return captured.headers[name];
    },
    status(code: number) {
      captured.statusCode = code;
      return res;
    },
    json(body: unknown) {
      captured.body = body;
      captured.ended = true;
      return res;
    },
    send(body: unknown) {
      captured.body = body;
      captured.ended = true;
      return res;
    },
    end(body?: unknown) {
      if (body !== undefined) captured.body = body;
      captured.ended = true;
      return res;
    },
    redirect(statusOrUrl: number | string, maybeUrl?: string) {
      if (typeof statusOrUrl === "number" && typeof maybeUrl === "string") {
        captured.statusCode = statusOrUrl;
        captured.redirectLocation = maybeUrl;
      } else if (typeof statusOrUrl === "string") {
        captured.statusCode = 302;
        captured.redirectLocation = statusOrUrl;
      }
      captured.ended = true;
      return res;
    },
  } as unknown as VercelResponse;

  return { res, captured };
}

export function getSetCookieHeader(captured: CapturedResponse): string | null {
  const v = captured.headers["Set-Cookie"];
  if (Array.isArray(v)) return v[0] ?? null;
  return (v as string) ?? null;
}

/**
 * Mint an HS256 JWT for tests. Lets test code construct tokens with
 * arbitrary claim shapes (e.g. cross-cutting `scope: "audit.write"`)
 * without going through `issueServiceToken`'s validator.
 */
export async function signTestToken(
  secret: string,
  claims: Record<string, unknown>,
): Promise<string> {
  const enc = (obj: unknown): string => {
    const json = typeof obj === "string" ? obj : JSON.stringify(obj);
    let b64: string;
    if (typeof Buffer !== "undefined") {
      b64 = Buffer.from(json, "utf8").toString("base64");
    } else {
      b64 = btoa(unescape(encodeURIComponent(json)));
    }
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const header = { alg: "HS256", typ: "JWT" } as const;
  const headerEnc = enc(header);
  const payloadEnc = enc(claims);
  const signingInput = `${headerEnc}.${payloadEnc}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(signingInput),
  );
  const sigBytes = new Uint8Array(sig);
  let bin = "";
  for (const b of sigBytes) bin += String.fromCharCode(b);
  const sigB64 = btoa(bin)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${signingInput}.${sigB64}`;
}
