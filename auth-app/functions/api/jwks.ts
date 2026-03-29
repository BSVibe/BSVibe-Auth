// Cloudflare Pages Function: proxy JWKS from Supabase
// Route: /api/jwks → Supabase JWKS endpoint

interface Env {
  SUPABASE_URL: string;
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const supabaseUrl = context.env.SUPABASE_URL;
  if (!supabaseUrl) {
    return new Response(
      JSON.stringify({ error: "SUPABASE_URL not configured" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }

  const jwksUrl = `${supabaseUrl}/auth/v1/.well-known/jwks.json`;
  const response = await fetch(jwksUrl, {
    headers: { "Accept": "application/json" },
  });

  if (!response.ok) {
    return new Response(
      JSON.stringify({ error: "Failed to fetch JWKS from upstream" }),
      { status: 502, headers: { "Content-Type": "application/json" } },
    );
  }

  const jwks = await response.json();
  return new Response(JSON.stringify(jwks), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=3600",
      "Access-Control-Allow-Origin": "*",
    },
  });
};
