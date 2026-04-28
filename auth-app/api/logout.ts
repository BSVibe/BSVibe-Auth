import type { VercelRequest, VercelResponse } from "./_lib/types";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    // No service key — can't invalidate server-side, just return OK
    res.setHeader("Access-Control-Allow-Origin", "*");
    return res.status(204).end();
  }

  // Extract user ID from the JWT (without verification — verification is caller's job)
  const authHeader = req.headers.authorization ?? "";
  const token = authHeader.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const payload = JSON.parse(
      Buffer.from(token.split(".")[1], "base64url").toString(),
    );
    const userId = payload.sub;

    if (userId) {
      await fetch(`${supabaseUrl}/auth/v1/admin/users/${userId}/logout`, {
        method: "POST",
        headers: {
          apikey: serviceRoleKey,
          Authorization: `Bearer ${serviceRoleKey}`,
          "Content-Type": "application/json",
        },
      });
    }
  } catch {
    // Best-effort — don't fail if Supabase call fails
  }

  res.setHeader("Access-Control-Allow-Origin", "*");
  return res.status(204).end();
}
