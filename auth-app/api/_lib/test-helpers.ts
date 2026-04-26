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
