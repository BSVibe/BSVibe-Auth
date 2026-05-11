/**
 * /oauth/authorize HTTP handler — wraps the preflightAuthorize +
 * commitConsent helpers in a Vercel-style request/response surface.
 *
 * GET — preflight (auth check, client + redirect + PKCE validation).
 *   * Not logged in    → 302 to ``/login?redirect=...``
 *   * Validation fail  → 302 to redirect_uri with ``?error=...`` (when
 *                        redirect_uri is known good) or HTML error
 *                        (when it isn't, since we can't trust it).
 *   * Validation pass  → render a simple consent HTML page (Approve /
 *                        Deny buttons that POST back to ``/oauth/authorize``)
 *   * Auto-approval for clients in TRUSTED_CLIENT_IDS — skips the
 *     consent UI to keep Claude-Code's UX one-click. Trusted clients
 *     are seeded server-side; never user-controllable.
 *
 * POST — commit consent (Approve / Deny). On Approve mints the code
 * and 302's back to redirect_uri.
 */

import type { VercelRequest, VercelResponse } from "@vercel/node";

import {
  commitConsent,
  defaultMatchRedirectUri,
  preflightAuthorize,
  type AuthorizeEnv,
  type AuthorizeOutcome,
  type AuthorizeRequest,
  type OAuthClientRow,
} from "./authorize";

// Clients allowed to skip the consent screen. Internal MCP clients only.
// Per-machine OAuth flow is still gated by the user's auth-server login;
// auto-approval just removes the "do you trust this app?" mid-flow modal
// for clients whose source code we ship.
const TRUSTED_CLIENT_IDS = new Set(["claude-code-mcp", "cli"]);

export interface AuthorizeHandlerDeps {
  resolveUser: (
    req: VercelRequest,
  ) => Promise<{ userId: string; tenantId: string | null } | null>;
  lookupClient: (clientId: string) => Promise<OAuthClientRow | null>;
}

export interface AuthorizeHandlerConfig {
  env: AuthorizeEnv;
  deps: AuthorizeHandlerDeps;
}

export function createAuthorizeHandler({ env, deps }: AuthorizeHandlerConfig) {
  const fullDeps = {
    ...deps,
    matchRedirectUri: defaultMatchRedirectUri,
  };

  return async function handler(req: VercelRequest, res: VercelResponse) {
    if (req.method !== "GET" && req.method !== "POST") {
      return res.status(405).json({ error: "method_not_allowed" });
    }

    const params = readParams(req);

    // POST with action=deny — short-circuit before consent commit so we
    // never mint a code on a denial.
    if (req.method === "POST" && readField(req, "action") === "deny") {
      if (params.redirect_uri) {
        const url = new URL(params.redirect_uri);
        url.searchParams.set("error", "access_denied");
        url.searchParams.set("error_description", "user denied the request");
        if (params.state) url.searchParams.set("state", params.state);
        return res.redirect(302, url.toString());
      }
      return res.status(400).send("access_denied (no redirect_uri to bounce to)");
    }

    const outcome = await preflightAuthorize(req, params, fullDeps);
    return await dispatch(req, res, env, params, outcome);
  };
}

async function dispatch(
  req: VercelRequest,
  res: VercelResponse,
  env: AuthorizeEnv,
  params: AuthorizeRequest,
  outcome: AuthorizeOutcome,
): Promise<void> {
  switch (outcome.kind) {
    case "redirect":
      res.redirect(302, outcome.location);
      return;
    case "render_error":
      res
        .status(outcome.status)
        .setHeader("content-type", "text/html; charset=utf-8")
        .send(renderErrorPage(outcome.error, outcome.description));
      return;
    case "needs_login":
      res.redirect(302, outcome.loginPath);
      return;
    case "needs_consent": {
      // Trusted clients skip consent and commit immediately.
      if (TRUSTED_CLIENT_IDS.has(outcome.client.client_id) || req.method === "POST") {
        const next = await commitConsent(env, {
          ...params,
          client: outcome.client,
          user: outcome.user,
          scope: outcome.scope,
          audience: outcome.audience,
        });
        return dispatch(req, res, env, params, next);
      }
      // Untrusted client + GET → render consent HTML.
      res
        .status(200)
        .setHeader("content-type", "text/html; charset=utf-8")
        .send(renderConsentPage(outcome.client, outcome.scope, outcome.audience, params));
      return;
    }
  }
}

function readParams(req: VercelRequest): AuthorizeRequest {
  const fromQuery = (req.query ?? {}) as Record<string, string | string[] | undefined>;
  const fromBody = (typeof req.body === "object" && req.body !== null ? (req.body as Record<string, unknown>) : {});
  const get = (k: string): string | undefined => {
    const q = fromQuery[k];
    if (Array.isArray(q)) return q[0];
    if (typeof q === "string") return q;
    const b = fromBody[k];
    return typeof b === "string" ? b : undefined;
  };
  return {
    response_type: get("response_type"),
    client_id: get("client_id"),
    redirect_uri: get("redirect_uri"),
    scope: get("scope"),
    state: get("state"),
    code_challenge: get("code_challenge"),
    code_challenge_method: get("code_challenge_method"),
    audience: get("audience"),
  };
}

function readField(req: VercelRequest, key: string): string | undefined {
  if (typeof req.body === "object" && req.body !== null) {
    const v = (req.body as Record<string, unknown>)[key];
    if (typeof v === "string") return v;
  }
  const q = (req.query ?? {}) as Record<string, string | string[] | undefined>;
  const qv = q[key];
  if (Array.isArray(qv)) return qv[0];
  if (typeof qv === "string") return qv;
  return undefined;
}

function renderConsentPage(
  client: OAuthClientRow,
  scope: string[],
  audience: string[],
  params: AuthorizeRequest,
): string {
  const esc = (s: string) =>
    s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  const scopeList = scope.length > 0 ? scope : ["(client default)"];
  const audList = audience.length > 0 ? audience : client.allowed_audiences;
  const hiddenInputs = Object.entries(params)
    .filter(([, v]) => typeof v === "string" && v.length > 0)
    .map(
      ([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v as string)}">`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Authorize ${esc(client.client_id)}</title>
<style>
body{font-family:system-ui,sans-serif;max-width:520px;margin:48px auto;padding:0 16px;color:#111}
h1{font-size:1.4rem}
.client{font-family:ui-monospace,Menlo,monospace;background:#f3f3f3;padding:.25rem .5rem;border-radius:.25rem}
ul{padding-left:1.25rem}
.actions{margin-top:1.5rem;display:flex;gap:.75rem}
button{padding:.5rem 1rem;border-radius:.375rem;border:1px solid #cdcdcd;background:#fff;cursor:pointer;font-size:1rem}
button.approve{background:#0070f3;color:#fff;border-color:#0070f3}
</style>
</head>
<body>
<h1>Authorize <span class="client">${esc(client.client_id)}</span></h1>
<p>This application is requesting access to your BSVibe account.</p>
<dl>
  <dt><strong>Scopes</strong></dt>
  <dd><ul>${scopeList.map((s) => `<li><code>${esc(s)}</code></li>`).join("")}</ul></dd>
  <dt><strong>Audience</strong></dt>
  <dd>${audList.map(esc).join(", ")}</dd>
</dl>
<form method="POST" action="/oauth/authorize">
  ${hiddenInputs}
  <div class="actions">
    <button type="submit" name="action" value="deny">Deny</button>
    <button type="submit" name="action" value="approve" class="approve">Approve</button>
  </div>
</form>
</body>
</html>`;
}

function renderErrorPage(error: string, description: string): string {
  const esc = (s: string) =>
    s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>OAuth error</title>
<style>body{font-family:system-ui,sans-serif;max-width:520px;margin:48px auto;padding:0 16px}
.code{font-family:ui-monospace,Menlo,monospace;background:#f3f3f3;padding:.25rem .5rem;border-radius:.25rem}</style>
</head><body><h1>OAuth error</h1>
<p>error: <span class="code">${esc(error)}</span></p>
<p>${esc(description)}</p>
</body></html>`;
}
