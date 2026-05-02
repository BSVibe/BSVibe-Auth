import type { VercelRequest, VercelResponse } from "./_lib/types";

const COOKIE_NAME = "bsvibe_session";

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

function getAllowedOrigins(): string[] {
  return (process.env.ALLOWED_REDIRECT_ORIGINS || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
}

function isAllowedRedirect(uri: string): boolean {
  let origin: string;
  try {
    origin = new URL(uri).origin;
  } catch {
    return false;
  }
  return getAllowedOrigins().some((entry) => {
    if (entry.endsWith(":*")) {
      const prefix = entry.slice(0, -2);
      return origin === prefix || origin.startsWith(prefix + ":");
    }
    return origin === entry;
  });
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const redirectUri = req.query.redirect_uri as string;
  if (!redirectUri || !isAllowedRedirect(redirectUri)) {
    return res.status(400).json({ error: "Invalid or missing redirect_uri" });
  }

  const errorRedirect = `${redirectUri}${redirectUri.includes("?") ? "&" : "?"}sso_error=login_required`;

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    return res.redirect(302, errorRedirect);
  }

  const cookies = parseCookies(req.headers.cookie ?? "");
  const refreshToken = cookies[COOKIE_NAME];

  if (!refreshToken) {
    return res.redirect(302, errorRedirect);
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
    res.setHeader(
      "Set-Cookie",
      `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
    );
    return res.redirect(302, errorRedirect);
  }

  const data = await resp.json();

  // Rotate session cookie
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${data.refresh_token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${30 * 24 * 60 * 60}`,
  );

  // Redirect back with tokens in hash fragment
  const qs = new URLSearchParams();
  qs.set("access_token", data.access_token);
  qs.set("refresh_token", data.refresh_token);
  qs.set("expires_in", String(data.expires_in));
  return res.redirect(302, `${redirectUri}#${qs.toString()}`);
}
