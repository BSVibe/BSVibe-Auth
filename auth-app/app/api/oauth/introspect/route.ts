/**
 * /oauth/introspect — RFC 7662 alias.
 *
 * Identical handler to /api/tokens/introspect; just the canonical OAuth
 * path so RFC 8414 discovery resolves the right URL.
 */

import introspectHandler from "@/lib/handlers/api-tokens/introspect";
import { vercelToRoute, type VercelStyleHandler } from "@/app/api/_adapter";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const route = vercelToRoute(introspectHandler as unknown as VercelStyleHandler);

export const POST = route;
export const OPTIONS = route;
