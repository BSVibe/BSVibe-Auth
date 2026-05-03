import dispatchHandler from '@/lib/handlers/alerts/dispatch';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const route = vercelToRoute(dispatchHandler as unknown as VercelStyleHandler);

export const POST = route;
export const OPTIONS = route;
