import type { VercelRequest, VercelResponse } from "./_lib/types";

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    return res.status(500).json({ error: "Auth service not configured" });
  }

  const { refresh_token } = (req.body ?? {}) as { refresh_token?: string };
  if (!refresh_token) {
    return res.status(400).json({ error: "refresh_token is required" });
  }

  const resp = await fetch(
    `${supabaseUrl}/auth/v1/token?grant_type=refresh_token`,
    {
      method: "POST",
      headers: {
        apikey: supabaseAnonKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ refresh_token }),
    },
  );

  if (!resp.ok) {
    return res.status(401).json({ error: "Invalid or expired refresh token" });
  }

  const data = await resp.json();
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  return res.status(200).json({
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_in: data.expires_in,
    token_type: "bearer",
  });
}
