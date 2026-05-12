import createHandler from "@/lib/handlers/oauth-clients/create";
import listHandler from "@/lib/handlers/oauth-clients/list";
import { vercelToRoute, type VercelStyleHandler } from "@/app/api/_adapter";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const POST = vercelToRoute(
  createHandler as unknown as VercelStyleHandler,
);
export const GET = vercelToRoute(
  listHandler as unknown as VercelStyleHandler,
);
export const OPTIONS = vercelToRoute(
  createHandler as unknown as VercelStyleHandler,
);
