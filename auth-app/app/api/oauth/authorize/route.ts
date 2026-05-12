import authorizeHandler from "@/lib/handlers/oauth/authorize_route";
import { vercelToRoute, type VercelStyleHandler } from "@/app/api/_adapter";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const route = vercelToRoute(authorizeHandler as unknown as VercelStyleHandler);

export const GET = route;
export const POST = route;
export const OPTIONS = route;
