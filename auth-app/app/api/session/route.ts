/**
 * Next.js Route Handler for /api/session.
 *
 * Wraps the default Vercel-style handler exported from `api/session.ts`,
 * which is itself produced by `createSessionHandler()`. Unit tests keep
 * exercising the factory directly with `makeReq/makeRes`.
 */

import sessionHandler from '@/api/session';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const route = vercelToRoute(sessionHandler as unknown as VercelStyleHandler);

export const GET = route;
export const POST = route;
export const DELETE = route;
export const OPTIONS = route;
