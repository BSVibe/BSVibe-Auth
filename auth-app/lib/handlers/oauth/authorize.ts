/**
 * OAuth 2.0 authorization endpoint (RFC 6749 §3.1, §4.1).
 *
 * Flow:
 *
 * 1. Client (e.g. Claude Code) redirects the user's browser here with
 *    ``response_type=code``, ``client_id``, ``redirect_uri``, ``scope``,
 *    ``state``, ``code_challenge``, ``code_challenge_method=S256``,
 *    optional ``audience``.
 * 2. We validate the request — known client + registered redirect_uri +
 *    S256 challenge + ``response_type=code``.
 * 3. We require the caller to have an authenticated session
 *    (BSVibe-Auth's normal Supabase cookie or wrapped session JWT). If
 *    not, we redirect to the existing ``/login?redirect=...`` flow,
 *    which kicks back here once authenticated.
 * 4. We render a tiny consent screen (client + scope + audience). User
 *    clicks Approve → we POST to /api/oauth/authorize (same surface)
 *    which calls ``issueAuthorizationCode`` and 302's to
 *    ``redirect_uri?code=...&state=...``.
 * 5. Client exchanges the code at ``/oauth/token`` with the matching
 *    ``code_verifier`` to get an access_token + refresh_token.
 *
 * Errors follow RFC 6749 §4.1.2.1 — when ``redirect_uri`` is known-good
 * we redirect back to the client with ``?error=...``; otherwise we
 * render a plain error page (so an attacker can't bounce errors to an
 * arbitrary URI by mangling the request).
 */

import type { VercelRequest } from "../_lib/types";

import {
  issueAuthorizationCode,
  type IssueAuthorizationCodeEnv,
} from "./authorization_code";

const ALLOWED_RESPONSE_TYPES = new Set(["code"]);
const ALLOWED_CODE_CHALLENGE_METHODS = new Set(["S256"]);

export type AuthorizeEnv = IssueAuthorizationCodeEnv;

export interface AuthorizeDeps {
  /** Resolves the authenticated user from request cookies/headers.
   *  Returns ``null`` when no valid session — caller should redirect to
   *  ``/login?redirect=...``. */
  resolveUser: (
    req: VercelRequest,
  ) => Promise<{ userId: string; tenantId: string | null } | null>;

  /** Look up the OAuth client by id. Returns ``null`` if unknown or
   *  revoked. */
  lookupClient: (clientId: string) => Promise<OAuthClientRow | null>;

  /** RFC 7591 — registered redirect_uris are stored on the client. The
   *  request's redirect_uri must match one of them exactly OR be a
   *  loopback URI (RFC 8252 §7.3) where only the port differs from a
   *  registered ``http://127.0.0.1/...`` template. */
  matchRedirectUri: (registered: string[], requested: string) => boolean;
}

export interface OAuthClientRow {
  client_id: string;
  client_type: "confidential" | "public";
  redirect_uris: string[] | null;
  allowed_scopes: string[];
  allowed_audiences: string[];
  revoked_at: string | null;
}

export interface AuthorizeRequest {
  response_type?: string;
  client_id?: string;
  redirect_uri?: string;
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  audience?: string;
}

export type AuthorizeOutcome =
  | { kind: "redirect"; location: string }
  | { kind: "render_error"; status: number; error: string; description: string }
  | { kind: "needs_login"; loginPath: string }
  | {
      kind: "needs_consent";
      client: OAuthClientRow;
      user: { userId: string; tenantId: string | null };
      scope: string[];
      audience: string[];
      state: string;
    };

/**
 * Pre-flight validation: returns either ``redirect`` (to login or back
 * to the client with an error) or ``needs_consent`` to advance the UI.
 */
export async function preflightAuthorize(
  req: VercelRequest,
  params: AuthorizeRequest,
  deps: AuthorizeDeps,
): Promise<AuthorizeOutcome> {
  // 1. response_type
  if (!params.response_type || !ALLOWED_RESPONSE_TYPES.has(params.response_type)) {
    return errorWithoutRedirect("unsupported_response_type", "response_type must be 'code'");
  }

  // 2. client_id known + not revoked
  if (!params.client_id) {
    return errorWithoutRedirect("invalid_request", "client_id is required");
  }
  const client = await deps.lookupClient(params.client_id);
  if (!client) {
    return errorWithoutRedirect("invalid_client", "unknown client");
  }
  if (client.revoked_at !== null) {
    return errorWithoutRedirect("invalid_client", "client has been revoked");
  }

  // 3. redirect_uri matches a registered one
  if (!params.redirect_uri) {
    return errorWithoutRedirect("invalid_request", "redirect_uri is required");
  }
  const registered = client.redirect_uris ?? [];
  if (registered.length === 0 || !deps.matchRedirectUri(registered, params.redirect_uri)) {
    return errorWithoutRedirect(
      "invalid_request",
      "redirect_uri is not registered for this client",
    );
  }

  // Past this point errors can safely 302 back to the client.
  const state = params.state ?? "";

  // 4. PKCE — S256 required.
  if (!params.code_challenge) {
    return errorViaRedirect(params.redirect_uri, state, "invalid_request", "code_challenge is required");
  }
  if (!params.code_challenge_method || !ALLOWED_CODE_CHALLENGE_METHODS.has(params.code_challenge_method)) {
    return errorViaRedirect(
      params.redirect_uri,
      state,
      "invalid_request",
      "code_challenge_method must be 'S256'",
    );
  }

  // 5. scope/audience within the client's allow-list.
  const requestedScope = (params.scope ?? "").split(/\s+/).filter(Boolean);
  for (const s of requestedScope) {
    if (!allowedByPrefix(client.allowed_scopes, s)) {
      return errorViaRedirect(params.redirect_uri, state, "invalid_scope", `scope not allowed: ${s}`);
    }
  }
  const requestedAud = (params.audience ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  for (const a of requestedAud) {
    if (!client.allowed_audiences.includes(a)) {
      return errorViaRedirect(params.redirect_uri, state, "invalid_request", `audience not allowed: ${a}`);
    }
  }

  // 6. Caller must be authenticated.
  const user = await deps.resolveUser(req);
  if (user === null) {
    // The login UX kicks back here once cookies are set. Use `next` (a
    // same-origin path) — LoginPage.tsx treats `next` as a safe in-app
    // bounce that DOESN'T receive tokens in the URL fragment.
    //
    // Build URLSearchParams from filtered entries — passing the whole
    // ``params`` object to URLSearchParams stringifies ``undefined`` as
    // the literal string ``"undefined"``, which then trips
    // ``audience`` / ``state`` validation on the post-login second pass
    // ("audience not allowed: undefined").
    const backParams = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (typeof v === "string" && v.length > 0) backParams.set(k, v);
    }
    const back = `/oauth/authorize?${backParams.toString()}`;
    return { kind: "needs_login", loginPath: `/login?next=${encodeURIComponent(back)}` };
  }

  return {
    kind: "needs_consent",
    client,
    user,
    scope: requestedScope,
    audience: requestedAud,
    state,
  };
}

export interface CommitConsentInput extends Omit<AuthorizeRequest, "scope" | "audience"> {
  // Already-validated values passed through from preflight.
  client: OAuthClientRow;
  user: { userId: string; tenantId: string | null };
  scope: string[];
  audience: string[];
}

export async function commitConsent(
  env: AuthorizeEnv,
  input: CommitConsentInput,
): Promise<AuthorizeOutcome> {
  const redirect_uri = input.redirect_uri!;
  const state = input.state ?? "";
  const { code } = await issueAuthorizationCode(env, {
    clientId: input.client.client_id,
    userId: input.user.userId,
    tenantId: input.user.tenantId,
    scope: input.scope,
    audience: input.audience.length > 0 ? input.audience : input.client.allowed_audiences,
    redirectUri: redirect_uri,
    codeChallenge: input.code_challenge!,
    codeChallengeMethod: "S256",
  });
  const url = new URL(redirect_uri);
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);
  return { kind: "redirect", location: url.toString() };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function errorWithoutRedirect(error: string, description: string): AuthorizeOutcome {
  return { kind: "render_error", status: 400, error, description };
}

function errorViaRedirect(
  redirectUri: string,
  state: string,
  error: string,
  description: string,
): AuthorizeOutcome {
  const url = new URL(redirectUri);
  url.searchParams.set("error", error);
  url.searchParams.set("error_description", description);
  if (state) url.searchParams.set("state", state);
  return { kind: "redirect", location: url.toString() };
}

function allowedByPrefix(allowed: string[], requested: string): boolean {
  // ``foo:bar`` matches ``foo:*`` or exactly ``foo:bar``.
  if (allowed.includes(requested)) return true;
  for (const a of allowed) {
    if (a.endsWith(":*") && requested.startsWith(a.slice(0, -1))) return true;
    if (a === "*") return true;
  }
  return false;
}

/**
 * RFC 8252 §7.3 — loopback redirect URIs MAY use any port. Pattern
 * registered as ``http://127.0.0.1/callback`` matches the requested
 * ``http://127.0.0.1:5173/callback``. Non-loopback URIs must match
 * exactly.
 */
export function defaultMatchRedirectUri(registered: string[], requested: string): boolean {
  if (registered.includes(requested)) return true;
  let reqUrl: URL;
  try {
    reqUrl = new URL(requested);
  } catch {
    return false;
  }
  const isLoopback =
    reqUrl.protocol === "http:" &&
    (reqUrl.hostname === "127.0.0.1" || reqUrl.hostname === "localhost" || reqUrl.hostname === "[::1]");
  if (!isLoopback) return false;
  for (const r of registered) {
    let rUrl: URL;
    try {
      rUrl = new URL(r);
    } catch {
      continue;
    }
    if (
      rUrl.protocol === reqUrl.protocol &&
      rUrl.hostname === reqUrl.hostname &&
      rUrl.pathname === reqUrl.pathname
    ) {
      return true;
    }
  }
  return false;
}
