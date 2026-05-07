import introspectHandler from '@/lib/handlers/api-tokens/introspect';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const route = vercelToRoute(introspectHandler as unknown as VercelStyleHandler);

export const POST = route;
export const OPTIONS = route;
