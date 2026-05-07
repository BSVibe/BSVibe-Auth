import deviceLookupHandler from '@/lib/handlers/oauth/device/lookup';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const route = vercelToRoute(deviceLookupHandler as unknown as VercelStyleHandler);

export const GET = route;
export const OPTIONS = route;
