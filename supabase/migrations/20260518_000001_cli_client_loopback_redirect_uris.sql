-- Tier 3.1 — enable authorization_code + PKCE loopback for the `cli` client.
--
-- Background. The `cli` public client was seeded in
-- 20260509_000001_oauth_clients_public_type.sql before the
-- `redirect_uris` column existed (added in 20260512_000001). It has
-- shipped through Phase 8 + Round 5 as device-flow only.
--
-- Tier 3.1 migrates every BSVibe CLI from RFC 8628 device flow to
-- RFC 7636 PKCE + RFC 8252 §7.3 loopback authorization_code. The
-- `bsvibe-cli-base` package (0.2.0) now binds 127.0.0.1:0 and registers
-- `http://127.0.0.1:<ephemeral>/callback` as the redirect URI. This row
-- needs the loopback patterns recorded so the authorize endpoint's
-- redirect-URI validator (defaultMatchRedirectUri in
-- auth-app/lib/handlers/oauth/authorize.ts) accepts them.
--
-- The validator already ignores the port for 127.0.0.1, localhost, and
-- [::1] per RFC 8252 §7.3 — the seeded URIs use port-less form so any
-- ephemeral port the kernel hands the CLI is accepted automatically.
-- This mirrors the `claude-code-mcp` seed in 20260513_000001.

update public.oauth_clients
set
  redirect_uris = array[
    'http://127.0.0.1/callback',
    'http://localhost/callback',
    'http://[::1]/callback'
  ],
  description = 'Public OAuth 2.0 client used by every BSVibe product CLI '
                '(bsgateway / bsage / bsnexus / bsupervisor login). '
                'Supports authorization_code + PKCE on a loopback redirect '
                '(RFC 7636 + RFC 8252). The RFC 8628 device-flow path is '
                'still served during the Tier 3.1 transition and removed in Tier 3.2.'
where client_id = 'cli';

comment on column public.oauth_clients.redirect_uris is
  'Allowed redirect URIs for authorization_code grant (RFC 6749 §3.1.2). '
  'NULL or empty array means the client is not allowed to use authorization_code. '
  'Public clients (RFC 8252) may register loopback URIs '
  '(http://127.0.0.1:<port>/callback) or custom-scheme URIs. '
  'Loopback host/port matching is permissive — the validator accepts any '
  'port for 127.0.0.1 / localhost / [::1] as long as the path matches.';
