import issueHandler from '@/lib/handlers/service-tokens/issue';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const route = vercelToRoute(issueHandler as unknown as VercelStyleHandler);

export const POST = route;
export const OPTIONS = route;
