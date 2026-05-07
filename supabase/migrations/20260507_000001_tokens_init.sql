-- Phase 1 — End-user/PAT tokens, refresh tokens, and OAuth device flow.
--
-- Three tables that together support the BSVibe-Auth token model documented
-- in ~/Docs/BSVibe_Phase1_Decisions_2026-05-07.md:
--
--   1. tokens           — opaque API keys (bsv_sk_/bsv_pk_) and PAT JWTs.
--                         Opaque tokens are stored as sha256(token_hash) +
--                         a 12-char prefix lookup column. PAT JWTs are
--                         signed HS256 with SERVICE_TOKEN_SIGNING_SECRET and
--                         tracked here by jti for revocation.
--   2. refresh_tokens   — single-use refresh tokens (sha256 hash). Rotation
--                         is atomic via PATCH ... WHERE used_at IS NULL.
--   3. device_codes     — RFC 8628 device authorization grant. The 'consumed'
--                         status enables atomic claim from /api/oauth/token.
--
-- All three tables enable RLS. Writes happen via the auth-app service role.
-- End-user JWTs may SELECT/UPDATE their own tokens but never see refresh
-- token hashes or device-code internals.

-- ---------------------------------------------------------------------------
-- tokens
-- ---------------------------------------------------------------------------
create table if not exists public.tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  tenant_id uuid not null,
  type text not null check (type in ('pat', 'api_key')),
  prefix text,
  token_hash bytea,
  jti uuid,
  audience jsonb not null default '[]'::jsonb,
  scopes jsonb not null default '[]'::jsonb,
  name text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz
);

create index if not exists tokens_prefix_idx
  on public.tokens (prefix)
  where token_hash is not null;

create index if not exists tokens_jti_idx
  on public.tokens (jti)
  where jti is not null;

create index if not exists tokens_user_idx
  on public.tokens (user_id, revoked_at);

alter table public.tokens enable row level security;

drop policy if exists tokens_select_own on public.tokens;
create policy tokens_select_own on public.tokens
  for select
  using (auth.uid() = user_id);

drop policy if exists tokens_update_own_revoke on public.tokens;
create policy tokens_update_own_revoke on public.tokens
  for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- INSERTs and DELETEs are service-role only (no policy defined → deny).

comment on table public.tokens is
  'End-user PATs and opaque API keys. Opaque tokens stored as sha256 hash + 12-char prefix; PAT JWTs tracked by jti for revocation.';
comment on column public.tokens.prefix is
  'First 12 characters of an opaque token (e.g. bsv_sk_abcde). NULL for PAT JWTs.';
comment on column public.tokens.token_hash is
  'sha256(raw_token) for opaque tokens. NULL for PAT JWTs.';
comment on column public.tokens.jti is
  'JWT ID for PAT JWTs. NULL for opaque tokens.';

-- ---------------------------------------------------------------------------
-- refresh_tokens — single-use rotation
-- ---------------------------------------------------------------------------
create table if not exists public.refresh_tokens (
  id uuid primary key default gen_random_uuid(),
  token_id uuid not null references public.tokens(id) on delete cascade,
  hash bytea not null,
  used_at timestamptz,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists refresh_tokens_token_id_idx
  on public.refresh_tokens (token_id);

alter table public.refresh_tokens enable row level security;

-- Service-role only. End-user JWTs never see refresh hashes.
-- No policies defined → deny by default.

comment on table public.refresh_tokens is
  'Single-use refresh tokens for PAT rotation. Atomic claim via PATCH ... WHERE used_at IS NULL.';
comment on column public.refresh_tokens.hash is
  'sha256(refresh_token_raw). Raw refresh token is returned to the client exactly once.';

-- ---------------------------------------------------------------------------
-- device_codes — RFC 8628 device authorization grant
-- ---------------------------------------------------------------------------
create table if not exists public.device_codes (
  device_code text primary key,
  user_code text unique not null,
  client_id text,
  scope jsonb not null default '[]'::jsonb,
  audience jsonb not null default '[]'::jsonb,
  user_id uuid,
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'denied', 'expired', 'consumed')),
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists device_codes_user_code_idx
  on public.device_codes (user_code);

alter table public.device_codes enable row level security;

-- Service-role only. The verify endpoint runs through the service role and
-- confirms the user_id matches auth.uid() at the application layer.
-- No policies defined → deny by default.

comment on table public.device_codes is
  'OAuth 2.0 Device Authorization Grant (RFC 8628). status=consumed enables atomic single-claim from /api/oauth/token.';
comment on column public.device_codes.status is
  'pending → approved|denied → consumed (terminal). expired set lazily by claim/poll path.';
