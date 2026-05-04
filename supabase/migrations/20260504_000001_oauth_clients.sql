-- Phase 1 — OAuth2 client_credentials grant for service-to-service auth.
--
-- Replaces the bootstrap pattern where 4 backends used a Supabase admin
-- access_token (1h expiry, refreshed by a launchd timer) to mint short-lived
-- service JWTs against /api/service-tokens/issue. Each backend now has a
-- dedicated OAuth client (e.g. bsgateway-prod) with a long-lived secret
-- managed in Vaultwarden, and exchanges it directly for service JWTs at
-- /api/oauth/token.
--
-- Decision: secrets are stored as PBKDF2-SHA256 hashes (Web Crypto, no
-- native bindings required for the Vercel function). Plaintext is shown
-- exactly once at provisioning time.

create table if not exists public.oauth_clients (
  client_id text primary key
    check (client_id ~ '^[a-z][a-z0-9_-]{2,63}$'),
  client_secret_hash text not null,
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  description text,
  allowed_audiences text[] not null
    check (array_length(allowed_audiences, 1) > 0),
  allowed_scopes text[] not null
    check (array_length(allowed_scopes, 1) > 0),
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  last_used_at timestamptz
);

create index if not exists oauth_clients_tenant_idx
  on public.oauth_clients (tenant_id)
  where revoked_at is null;

-- ---------------------------------------------------------------------------
-- Row Level Security: end-user JWTs MUST NOT see this table at all. The
-- /api/oauth/token handler reads oauth_clients via the service-role key.
-- ---------------------------------------------------------------------------
alter table public.oauth_clients enable row level security;

-- No SELECT/INSERT/UPDATE/DELETE policies are defined. Service role bypasses
-- RLS; everything else is denied by default.

-- ---------------------------------------------------------------------------
-- touch_oauth_client_last_used: bump last_used_at on successful token mint.
-- Called from the handler with the service role.
-- ---------------------------------------------------------------------------
create or replace function public.touch_oauth_client_last_used(p_client_id text)
returns void
language sql
security definer
set search_path = public
as $$
  update public.oauth_clients
     set last_used_at = now()
   where client_id = p_client_id
     and revoked_at is null;
$$;

-- ---------------------------------------------------------------------------
-- comment markers — make grep'ing for the deprecation easy.
-- ---------------------------------------------------------------------------
comment on table public.oauth_clients is
  'OAuth2 client_credentials grant clients (Phase 1). One row per backend (bsgateway-prod, bsnexus-prod, ...). Replaces the BSVIBE_SERVICE_ACCOUNT_TOKEN bootstrap.';
comment on column public.oauth_clients.client_secret_hash is
  'PBKDF2-SHA256 encoded hash. Format: pbkdf2-sha256$<iter>$<salt-b64url>$<hash-b64url>. Plaintext is shown exactly once at provisioning.';
comment on column public.oauth_clients.allowed_audiences is
  'Subset of SERVICE_AUDIENCES (bsage|bsgateway|bsupervisor|bsnexus|bsvibe-auth) the client may request a token for.';
comment on column public.oauth_clients.allowed_scopes is
  'Scope identifiers the client may request, e.g. {bsupervisor.audit.write, bsage.read}. Each scope must be prefixed with one of allowed_audiences (enforced at issuance).';
