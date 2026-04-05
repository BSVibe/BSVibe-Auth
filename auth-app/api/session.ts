import type { VercelRequest, VercelResponse } from "@vercel/node";

const COOKIE_NAME = "bsvibe_session";
const COOKIE_MAX_AGE = 30 * 24 * 60 * 60; // 30 days

function getAllowedOrigins(): string[] {
  return (process.env.ALLOWED_REDIRECT_ORIGINS || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
}

function getCorsOrigin(req: VercelRequest): string | null {
  const origin = req.headers.origin;
  if (!origin) return null;

  const allowed = getAllowedOrigins();
  const isAllowed = allowed.some((entry) => {
    if (entry.endsWith(":*")) {
      const prefix = entry.slice(0, -2);
      return origin === prefix || origin.startsWith(prefix + ":");
    }
    return origin === entry;
  });

  return isAllowed ? origin : null;
}

function setCorsHeaders(res: VercelResponse, origin: string | null): void {
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  const corsOrigin = getCorsOrigin(req);
  setCorsHeaders(res, corsOrigin);

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    return res.status(500).json({ error: "Auth service not configured" });
  }

  // POST — set session cookie with refresh_token
  if (req.method === "POST") {
    const { refresh_token } = req.body ?? {};
    if (!refresh_token) {
      return res.status(400).json({ error: "refresh_token is required" });
    }

    res.setHeader(
      "Set-Cookie",
      `${COOKIE_NAME}=${refresh_token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${COOKIE_MAX_AGE}`,
    );
    return res.status(200).json({ ok: true });
  }

  // GET — validate session cookie, refresh tokens, return fresh tokens
  if (req.method === "GET") {
    const cookies = parseCookies(req.headers.cookie ?? "");
    const refreshToken = cookies[COOKIE_NAME];

    if (!refreshToken) {
      return res.status(401).json({ error: "No session" });
    }

    const resp = await fetch(
      `${supabaseUrl}/auth/v1/token?grant_type=refresh_token`,
      {
        method: "POST",
        headers: {
          apikey: supabaseAnonKey,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ refresh_token: refreshToken }),
      },
    );

    if (!resp.ok) {
      // Clear invalid cookie
      res.setHeader(
        "Set-Cookie",
        `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0`,
      );
      return res.status(401).json({ error: "Session expired" });
    }

    const data = await resp.json();

    // Update cookie with new refresh token
    res.setHeader(
      "Set-Cookie",
      `${COOKIE_NAME}=${data.refresh_token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${COOKIE_MAX_AGE}`,
    );

    return res.status(200).json({
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: data.expires_in,
    });
  }

  // DELETE — clear session cookie
  if (req.method === "DELETE") {
    res.setHeader(
      "Set-Cookie",
      `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0`,
    );
    return res.status(200).json({ ok: true });
  }

  return res.status(405).json({ error: "Method not allowed" });
}

function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const pair of cookieHeader.split(";")) {
    const [key, ...rest] = pair.trim().split("=");
    if (key) {
      cookies[key] = rest.join("=");
    }
  }
  return cookies;
}
