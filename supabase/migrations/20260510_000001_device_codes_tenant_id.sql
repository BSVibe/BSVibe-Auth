-- Phase 8.0 — store the approving user's tenant on the device_codes row.
--
-- Without this column the device-code grant has no way to mint a PAT
-- tenant claim for public clients (the canonical `cli` row carries
-- ``tenant_id IS NULL``). On ``/oauth/device/verify`` approve we look up
-- the authenticated user's primary tenant_membership and stamp it here;
-- the device-code grant then forwards it to the PAT.
--
-- The column is nullable + has no default. Pre-existing rows retain
-- ``tenant_id = NULL`` (they are pending or expired anyway), and the
-- grant handler still falls back to the client row's ``tenant_id`` when
-- the device row hasn't been re-stamped (covers the in-flight upgrade
-- window between this migration applying and the `verify` handler
-- redeploy).

alter table public.device_codes
  add column if not exists tenant_id uuid
    references public.tenants(id) on delete set null;

create index if not exists device_codes_tenant_idx
  on public.device_codes (tenant_id)
  where status = 'approved';

comment on column public.device_codes.tenant_id is
  'User-selected tenant captured at /oauth/device/verify approve. Drives the PAT''s tenant claim for public clients (RFC 8628 device-flow CLIs); confidential clients keep using oauth_clients.tenant_id.';
