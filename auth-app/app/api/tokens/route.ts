import listTokensHandler from '@/lib/handlers/api-tokens/list';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const listRoute = vercelToRoute(listTokensHandler as unknown as VercelStyleHandler);

export const GET = listRoute;
export const OPTIONS = listRoute;
