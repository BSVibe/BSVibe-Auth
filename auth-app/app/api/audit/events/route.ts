import eventsHandler from '@/lib/handlers/audit/events';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const route = vercelToRoute(eventsHandler as unknown as VercelStyleHandler);

export const POST = route;
export const OPTIONS = route;
