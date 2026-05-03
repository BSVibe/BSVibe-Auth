/**
 * Vercel-compatible request/response types.
 *
 * Phase Z: previously these came from `@vercel/node`, which we dropped when
 * migrating off the Vite + Vercel serverless setup. The handler factories
 * (e.g. `createSessionHandler`) only need a thin contract, so we declare it
 * here. Tests import these instead of `@vercel/node`, and the Next.js Route
 * Handler adapter (`app/api/_adapter.ts`) builds a matching object.
 *
 * Headers and query are typed as `string | undefined` (the common Vercel
 * runtime shape) — multi-value headers, when present, arrive as a single
 * comma-joined string. This matches what the handlers already assume.
 */

export interface VercelRequest {
  method?: string;
  headers: Record<string, string | undefined>;
  query: Record<string, string | undefined>;
  body: unknown;
  cookies: Record<string, string>;
  url?: string;
}

export interface VercelResponse {
  setHeader(name: string, value: string | string[]): VercelResponse;
  getHeader(name: string): string | string[] | undefined;
  status(code: number): VercelResponse;
  json(body: unknown): VercelResponse;
  send(body: unknown): VercelResponse;
  end(body?: unknown): VercelResponse;
  redirect(statusOrUrl: number | string, maybeUrl?: string): VercelResponse;
}
