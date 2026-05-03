import rulesHandler from '@/lib/handlers/alerts/rules';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const route = vercelToRoute(rulesHandler as unknown as VercelStyleHandler);

export const PATCH = route;
export const DELETE = route;
export const OPTIONS = route;
