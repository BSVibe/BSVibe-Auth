import silentCheckHandler from '@/api/silent-check';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const route = vercelToRoute(silentCheckHandler as unknown as VercelStyleHandler);

export const GET = route;
export const OPTIONS = route;
