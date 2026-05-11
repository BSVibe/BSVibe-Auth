-- Round 5 — OAuth 2.0 authorization_code grant w/ PKCE.
--
-- The first four BSVibe product MCP servers (gateway, sage, supervisor,
-- nexus) need a way for Claude Code (and any other in-browser MCP client)
-- to obtain a user-scoped access token without the user manually copying
-- one from a dashboard. Authorization code w/ PKCE + RFC 9728 discovery is
-- the canonical pattern; this migration adds the storage the new endpoints
-- need.
--
-- Two pieces:
--   1. ``redirect_uris`` column on ``oauth_clients`` — public clients
--      that use authorization_code register the exact URIs they're
--      allowed to redirect to (RFC 6749 §3.1.2, RFC 8252 §7.3).
--   2. ``oauth_codes`` table — short-lived (10 min) authorization codes
--      bound to a single client + redirect_uri + PKCE code_challenge.
--      Single-use (``used_at`` flips on consumption).

alter table public.oauth_clients
  add column if not exists redirect_uris text[];

-- Existing rows have no redirect_uris (NULL) — confidential / device-flow
-- clients don't use authorization_code so that's fine. A handler-level
-- check refuses authorization_code dispatch when redirect_uris is empty.

comment on column public.oauth_clients.redirect_uris is
  'Allowed redirect URIs for authorization_code grant (RFC 6749 §3.1.2). '
  'NULL or empty array means the client is not allowed to use authorization_code. '
  'Public clients (RFC 8252) may register loopback URIs '
  '(http://127.0.0.1:<port>/callback) or custom-scheme URIs.';

-- ---------------------------------------------------------------------------
-- Authorization codes
-- ---------------------------------------------------------------------------
create table if not exists public.oauth_codes (
  -- The actual ``code`` value the authorize endpoint emits back to the
  -- client. base64url-encoded random bytes; constant-time lookup.
  code text primary key,

  client_id text not null
    references public.oauth_clients(client_id) on delete cascade,

  -- The principal that approved at /oauth/authorize. Pulled from the
  -- authenticated session at the time of approval and frozen here so a
  -- session rotation between authorize + token exchange can't move the
  -- minted token to a different identity.
  user_id text not null,

  -- Tenant the user will operate against once the access token is minted.
  -- NULL when the user belongs to no tenants (handler converts to
  -- ``invalid_request`` before persisting; this NULL column shouldn't
  -- show up in practice but is here for completeness).
  tenant_id uuid references public.tenants(id) on delete cascade,

  -- Scope + audience requested at /authorize. Same shape the device-flow
  -- emits onto device_codes; the token handler reads these verbatim
  -- when minting the PAT JWT.
  scope text[] not null,
  audience text[] not null,

  -- The exact ``redirect_uri`` the client used at /authorize. The token
  -- exchange MUST present the same one (RFC 6749 §4.1.3).
  redirect_uri text not null,

  -- PKCE binding (RFC 7636 §4.1) — code_challenge + method. The token
  -- exchange verifies the client knows the code_verifier that produced
  -- this challenge under this method. ``S256`` is enforced at the
  -- handler level (no ``plain`` for public clients).
  code_challenge text not null,
  code_challenge_method text not null
    check (code_challenge_method in ('S256')),

  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at timestamptz
);

-- Lookup by primary key only; no other indexes needed (codes are opaque
-- random, no enumeration vector).

comment on table public.oauth_codes is
  'OAuth 2.0 authorization_code grant rows (RFC 6749 §4.1, RFC 7636 PKCE). '
  'Single-use, 10-minute TTL. Consumed via atomic PATCH (used_at IS NULL → set used_at).';

-- ---------------------------------------------------------------------------
-- RLS: end-user JWTs MUST NOT see this table. Server-role-only.
-- ---------------------------------------------------------------------------
alter table public.oauth_codes enable row level security;
-- No policies declared. Service role bypasses RLS; everything else is denied.
