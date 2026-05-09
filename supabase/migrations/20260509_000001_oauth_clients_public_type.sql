-- Phase 8.0 — public RFC 8628 clients in oauth_clients.
--
-- The original oauth_clients table (20260504) was scoped to confidential
-- service-to-service backends: each row required a tenant binding + a
-- PBKDF2-hashed client_secret. RFC 8628 device-flow CLIs are public clients
-- (no secret survives shipping with the binary), and the PAT minted on
-- approval inherits its tenant from the *user* who approved (not the
-- client), so the per-row tenant_id is meaningless for those rows.
--
-- This migration:
--   1. Adds `client_type` ('confidential' | 'public') with a default that
--      preserves the existing row semantics ('confidential' for the four
--      pre-existing service backends).
--   2. Drops NOT NULL from `client_secret_hash` and `tenant_id` so public
--      rows can omit them.
--   3. Adds a CHECK that confidential rows still carry both fields — the
--      old constraint moves from the column level to a row-level invariant.
--   4. Seeds the canonical `cli` public client used by every BSVibe product
--      CLI (`bsgateway login`, `bsage login`, etc.).

alter table public.oauth_clients
  add column if not exists client_type text not null default 'confidential'
    check (client_type in ('confidential', 'public'));

alter table public.oauth_clients
  alter column client_secret_hash drop not null;

alter table public.oauth_clients
  alter column tenant_id drop not null;

-- Pre-existing rows are confidential (default) — invariant remains intact.
-- Public rows have a NULL client_secret_hash and a NULL tenant_id; the
-- CHECK below stays loose for them and tight for everything else.
alter table public.oauth_clients
  drop constraint if exists oauth_clients_confidential_complete;

alter table public.oauth_clients
  add constraint oauth_clients_confidential_complete
    check (
      client_type = 'public'
      or (client_secret_hash is not null and tenant_id is not null)
    );

comment on column public.oauth_clients.client_type is
  'OAuth client class. ''confidential'' (default) requires client_secret_hash + tenant_id (service-to-service). ''public'' is for RFC 8628 device-flow clients shipped to end-users — no secret, tenant comes from the approving user at /api/oauth/device/token.';

-- ---------------------------------------------------------------------------
-- Seed: the canonical CLI client for `<product> login`.
-- Idempotent — re-running the migration leaves an existing row untouched.
-- ---------------------------------------------------------------------------
insert into public.oauth_clients (
  client_id,
  client_type,
  client_secret_hash,
  tenant_id,
  description,
  allowed_audiences,
  allowed_scopes
)
values (
  'cli',
  'public',
  null,
  null,
  'Public RFC 8628 device-flow client used by every BSVibe product CLI (bsgateway / bsage / bsnexus / bsupervisor login).',
  array['gateway', 'sage', 'nexus', 'supervisor', 'bsvibe-auth'],
  array['gateway:*', 'sage:*', 'nexus:*', 'supervisor:*', 'bsvibe-auth:*']
)
on conflict (client_id) do nothing;
