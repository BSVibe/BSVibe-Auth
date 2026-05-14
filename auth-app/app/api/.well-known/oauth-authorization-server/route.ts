/**
 * RFC 8414 OAuth 2.0 Authorization Server Metadata.
 *
 * Served at the canonical /.well-known/oauth-authorization-server path
 * (rewritten in next.config.mjs). MCP clients (Claude Code et al.) read
 * this after they hit a 401 with WWW-Authenticate referencing this
 * issuer, and use the discovered endpoints to drive the OAuth code +
 * PKCE flow.
 *
 * Static JSON. The issuer + endpoints are derived from the request host
 * so the same code serves prod (auth.bsvibe.dev) and any preview deploy.
 */

import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function resolveIssuer(req: NextRequest): string {
  const envIssuer = process.env.OAUTH_ISSUER ?? process.env.SERVICE_TOKEN_ISSUER;
  if (envIssuer) return envIssuer.replace(/\/$/, "");
  const proto =
    req.headers.get("x-forwarded-proto") ??
    (req.url.startsWith("https") ? "https" : "http");
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
  return host ? `${proto}://${host}` : "https://auth.bsvibe.dev";
}

export async function GET(req: NextRequest): Promise<NextResponse> {
  const issuer = resolveIssuer(req);
  const body = {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oauth/register`,
    introspection_endpoint: `${issuer}/oauth/introspect`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: [
      "authorization_code",
      "refresh_token",
      "client_credentials",
      "urn:ietf:params:oauth:grant-type:device_code",
    ],
    token_endpoint_auth_methods_supported: [
      "none",
      "client_secret_basic",
      "client_secret_post",
    ],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [
      "bsgateway:*",
      "bsage:*",
      "bsnexus:*",
      "bsupervisor:*",
      "openid",
      "profile",
      "email",
    ],
    service_documentation: "https://auth.bsvibe.dev",
  };
  return NextResponse.json(body, {
    status: 200,
    headers: {
      "Cache-Control": "public, max-age=300",
    },
  });
}

export async function OPTIONS(): Promise<NextResponse> {
  return new NextResponse(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}
