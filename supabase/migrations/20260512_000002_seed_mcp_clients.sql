-- Round 5 — seed canonical OAuth 2.0 authorization_code clients.
--
-- These rows are the trusted, server-side-shipped MCP clients that
-- Claude Code (and future first-party IDE plugins) use to obtain a
-- user PAT via the on-connect OAuth flow. Public (RFC 8252) — no
-- client_secret. PKCE is the only authentication factor.
--
-- Idempotent — re-running the migration leaves an existing row
-- untouched.

insert into public.oauth_clients (
  client_id,
  client_type,
  client_secret_hash,
  tenant_id,
  description,
  allowed_audiences,
  allowed_scopes,
  redirect_uris
)
values (
  'claude-code-mcp',
  'public',
  null,
  null,
  'Anthropic Claude Code MCP client. Obtains a user PAT via authorization_code + PKCE; cannot use client_credentials.',
  array['gateway', 'sage', 'nexus', 'supervisor'],
  array['gateway:*', 'sage:*', 'nexus:*', 'supervisor:*'],
  array[
    'http://127.0.0.1/callback',
    'http://localhost/callback',
    'http://[::1]/callback'
  ]
)
on conflict (client_id) do nothing;
