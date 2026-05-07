import deviceVerifyHandler from '@/lib/handlers/oauth/device/verify';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const route = vercelToRoute(deviceVerifyHandler as unknown as VercelStyleHandler);

export const POST = route;
export const OPTIONS = route;
