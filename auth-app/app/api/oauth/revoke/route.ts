import revokeHandler from "@/lib/handlers/oauth/revoke";
import { vercelToRoute, type VercelStyleHandler } from "@/app/api/_adapter";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const route = vercelToRoute(revokeHandler as unknown as VercelStyleHandler);

export const POST = route;
export const OPTIONS = route;
