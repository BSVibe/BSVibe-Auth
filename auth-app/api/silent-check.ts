import type { VercelRequest, VercelResponse } from "@vercel/node";

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

function validateOrigin(origin: string): boolean {
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

  const parentOrigin = (req.query.origin as string) || "*";
  if (parentOrigin !== "*" && !validateOrigin(parentOrigin)) {
    return sendHtml(res, { error: "login_required" }, "*");
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseAnonKey) {
    return sendHtml(res, { error: "login_required" }, parentOrigin);
  }

  const cookies = parseCookies(req.headers.cookie ?? "");
  const refreshToken = cookies[COOKIE_NAME];

  if (!refreshToken) {
    return sendHtml(res, { error: "login_required" }, parentOrigin);
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
    return sendHtml(res, { error: "login_required" }, parentOrigin);
  }

  const data = await resp.json();

  // Update cookie with new refresh token
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${data.refresh_token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${30 * 24 * 60 * 60}`,
  );

  return sendHtml(res, {
    access_token: data.access_token,
    refresh_token: data.refresh_token,
    expires_in: data.expires_in,
  }, parentOrigin);
}

function sendHtml(
  res: VercelResponse,
  payload: { error: string } | { access_token: string; refresh_token: string; expires_in: number },
  targetOrigin: string,
): void {
  const message = JSON.stringify({ type: "bsvibe-auth", ...payload });
  const escapedOrigin = JSON.stringify(targetOrigin);
  const html = `<!DOCTYPE html>
<html>
<head><title>BSVibe SSO</title></head>
<body>
<script>
  window.parent.postMessage(${message}, ${escapedOrigin});
</script>
</body>
</html>`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.status(200).send(html);
}
