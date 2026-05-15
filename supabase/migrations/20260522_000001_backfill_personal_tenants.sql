-- Tier 4 Phase 2 — backfill personal tenants for existing auth.users.
--
-- Phase 1 (20260521_000001_ensure_personal_tenant_fn.sql + #44/#45/#47)
-- wired runtime provisioning so every fresh sign-in calls
-- public.ensure_personal_tenant. That covers new users and any
-- existing user who logs in again.
--
-- This one-off backfill closes the gap for confirmed-but-dormant
-- accounts that may never re-authenticate before being needed. It
-- reuses the same SECURITY DEFINER function so every code path —
-- /api/session POST hook, defensive /authorize hook, this migration —
-- shares one atomic implementation.
--
-- Filter rationale:
--   - skip rows where confirmed_at is null — unverified signups should
--     re-acquire via the runtime path on their first confirmed login;
--     creating a personal tenant for an unverified email would
--     allocate state to an account that may never come back, and is
--     also a small spam-amplification surface.
--   - skip rows where deleted_at is not null — Supabase soft-delete
--     parity (public.tenants has its own deleted_at, but the
--     auth.users source-of-truth tombstone is what we honour here).
--
-- Idempotent: re-running after Phase 1 is a no-op because the runtime
-- path already provisioned each subsequently-logged-in user, and the
-- function short-circuits when an existing membership is found.

do $$
declare
  u record;
  display text;
begin
  for u in
    select id, email
    from auth.users au
    where au.deleted_at is null
      and au.confirmed_at is not null
      and not exists (
        select 1 from public.tenant_members tm where tm.user_id = au.id
      )
  loop
    display := coalesce(nullif(split_part(u.email, '@', 1), ''), 'Personal');
    perform public.ensure_personal_tenant(u.id, display);
  end loop;
end $$;
