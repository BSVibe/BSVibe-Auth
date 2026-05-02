/**
 * Vercel handler → Next.js Route Handler adapter.
 *
 * Phase Z: this app's API handlers were originally written against the
 * `@vercel/node` `(req, res)` signature so they could be unit-tested with
 * lightweight req/res shims. Migrating to Next.js 15 Route Handlers means
 * exporting `GET/POST/...` functions that receive a `Request` and return a
 * `Response` — a different shape entirely.
 *
 * Rather than rewrite (and re-test) every handler, we wrap each Vercel-style
 * handler with `vercelToRoute()`. The unit tests keep using the original
 * factories (`createSessionHandler({ ... })`) with `makeReq`/`makeRes`, while
 * production traffic flows through the Next.js Route Handler.
 *
 * No serverless-specific feature is lost: `cookies`, `headers`, query, body
 * (JSON or form), redirects, status codes are all supported.
 */

import type { NextRequest } from 'next/server';

interface VercelLikeReq {
  method: string;
  headers: Record<string, string>;
  query: Record<string, string>;
  body: unknown;
  cookies: Record<string, string>;
  url?: string;
}

interface CapturedRes {
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: unknown;
  ended: boolean;
  redirectLocation?: string;
  bodyIsJson: boolean;
}

interface VercelLikeRes {
  setHeader: (name: string, value: string | string[]) => VercelLikeRes;
  getHeader: (name: string) => string | string[] | undefined;
  status: (code: number) => VercelLikeRes;
  json: (body: unknown) => VercelLikeRes;
  send: (body: unknown) => VercelLikeRes;
  end: (body?: unknown) => VercelLikeRes;
  redirect: (statusOrUrl: number | string, maybeUrl?: string) => VercelLikeRes;
}

export type VercelStyleHandler = (
  req: VercelLikeReq,
  res: VercelLikeRes,
) => Promise<unknown> | unknown;

function parseCookieHeader(header: string | null): Record<string, string> {
  if (!header) return {};
  const out: Record<string, string> = {};
  for (const pair of header.split(';')) {
    const [k, ...rest] = pair.trim().split('=');
    if (k) out[k] = rest.join('=');
  }
  return out;
}

async function buildVercelReq(req: NextRequest): Promise<VercelLikeReq> {
  const headers: Record<string, string> = {};
  req.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  const url = new URL(req.url);
  const query: Record<string, string> = {};
  url.searchParams.forEach((value, key) => {
    query[key] = value;
  });

  let body: unknown = undefined;
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'OPTIONS') {
    const contentType = headers['content-type'] || '';
    if (contentType.includes('application/json')) {
      try {
        body = await req.json();
      } catch {
        body = undefined;
      }
    } else if (contentType.includes('application/x-www-form-urlencoded')) {
      const text = await req.text();
      const parsed = new URLSearchParams(text);
      const obj: Record<string, string> = {};
      parsed.forEach((v, k) => {
        obj[k] = v;
      });
      body = obj;
    } else {
      try {
        body = await req.text();
      } catch {
        body = undefined;
      }
    }
  }

  const cookies = parseCookieHeader(headers['cookie'] || null);

  return {
    method: req.method,
    headers,
    query,
    body,
    cookies,
    url: req.url,
  };
}

function makeCapturingRes(): { res: VercelLikeRes; captured: CapturedRes } {
  const captured: CapturedRes = {
    statusCode: 200,
    headers: {},
    body: undefined,
    ended: false,
    bodyIsJson: false,
  };

  const res: VercelLikeRes = {
    setHeader(name, value) {
      captured.headers[name] = value;
      return res;
    },
    getHeader(name) {
      return captured.headers[name];
    },
    status(code) {
      captured.statusCode = code;
      return res;
    },
    json(body) {
      captured.body = body;
      captured.bodyIsJson = true;
      captured.ended = true;
      return res;
    },
    send(body) {
      captured.body = body;
      captured.ended = true;
      return res;
    },
    end(body) {
      if (body !== undefined) captured.body = body;
      captured.ended = true;
      return res;
    },
    redirect(statusOrUrl, maybeUrl) {
      if (typeof statusOrUrl === 'number' && typeof maybeUrl === 'string') {
        captured.statusCode = statusOrUrl;
        captured.redirectLocation = maybeUrl;
      } else if (typeof statusOrUrl === 'string') {
        captured.statusCode = 302;
        captured.redirectLocation = statusOrUrl;
      }
      captured.ended = true;
      return res;
    },
  };

  return { res, captured };
}

function buildResponse(captured: CapturedRes): Response {
  const responseHeaders = new Headers();

  for (const [name, value] of Object.entries(captured.headers)) {
    if (Array.isArray(value)) {
      for (const v of value) responseHeaders.append(name, v);
    } else {
      responseHeaders.set(name, value);
    }
  }

  if (captured.redirectLocation) {
    responseHeaders.set('Location', captured.redirectLocation);
    return new Response(null, {
      status: captured.statusCode || 302,
      headers: responseHeaders,
    });
  }

  if (captured.bodyIsJson) {
    if (!responseHeaders.has('Content-Type')) {
      responseHeaders.set('Content-Type', 'application/json');
    }
    return new Response(JSON.stringify(captured.body ?? null), {
      status: captured.statusCode,
      headers: responseHeaders,
    });
  }

  if (captured.body === undefined || captured.body === null) {
    return new Response(null, {
      status: captured.statusCode,
      headers: responseHeaders,
    });
  }

  if (typeof captured.body === 'string') {
    return new Response(captured.body, {
      status: captured.statusCode,
      headers: responseHeaders,
    });
  }

  return new Response(JSON.stringify(captured.body), {
    status: captured.statusCode,
    headers: responseHeaders,
  });
}

/**
 * Wrap a Vercel-style `(req, res)` handler so Next.js can call it as a
 * Route Handler.
 */
export function vercelToRoute(
  handler: VercelStyleHandler,
): (req: NextRequest) => Promise<Response> {
  return async (req: NextRequest) => {
    const vercelReq = await buildVercelReq(req);
    const { res, captured } = makeCapturingRes();
    await handler(vercelReq, res);
    return buildResponse(captured);
  };
}
