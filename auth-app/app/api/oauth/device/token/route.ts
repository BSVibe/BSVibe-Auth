/**
 * RFC 8628 §3.4 device-grant polling endpoint.
 *
 * Forwards to the same extended OAuth token handler as `/api/oauth/token`,
 * which dispatches by `grant_type` and supports
 * `urn:ietf:params:oauth:grant-type:device_code`. Exposing the device-grant
 * under `/oauth/device/token` is conventional for RFC 8628 deployments while
 * the spec-required `/oauth/token` alias remains available for clients that
 * prefer the unified endpoint.
 */
import tokenHandler from '@/lib/handlers/oauth/token';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const route = vercelToRoute(tokenHandler as unknown as VercelStyleHandler);

export const POST = route;
export const OPTIONS = route;
