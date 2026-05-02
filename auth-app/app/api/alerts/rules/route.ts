import rulesHandler from '@/api/alerts/rules';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const route = vercelToRoute(rulesHandler as unknown as VercelStyleHandler);

export const GET = route;
export const POST = route;
export const OPTIONS = route;
