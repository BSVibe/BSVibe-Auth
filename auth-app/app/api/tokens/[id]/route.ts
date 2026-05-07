import showTokenHandler from '@/lib/handlers/api-tokens/show';
import revokeTokenHandler from '@/lib/handlers/api-tokens/revoke';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const showRoute = vercelToRoute(showTokenHandler as unknown as VercelStyleHandler);
const revokeRoute = vercelToRoute(revokeTokenHandler as unknown as VercelStyleHandler);

export const GET = showRoute;
export const DELETE = revokeRoute;
export const OPTIONS = showRoute;
