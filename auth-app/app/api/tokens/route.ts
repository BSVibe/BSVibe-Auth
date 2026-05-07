import createTokenHandler from '@/lib/handlers/api-tokens/create';
import listTokensHandler from '@/lib/handlers/api-tokens/list';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const createRoute = vercelToRoute(createTokenHandler as unknown as VercelStyleHandler);
const listRoute = vercelToRoute(listTokensHandler as unknown as VercelStyleHandler);

export const POST = createRoute;
export const GET = listRoute;
export const OPTIONS = createRoute;
