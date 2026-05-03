import switchTenantHandler from '@/lib/handlers/session/switch_tenant';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const route = vercelToRoute(switchTenantHandler as unknown as VercelStyleHandler);

export const POST = route;
export const OPTIONS = route;
