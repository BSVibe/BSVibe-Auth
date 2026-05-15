-- Tier 4 — atomic helper for runtime tenant provisioning on user sign-in.
--
-- Phase 0 P0.2 shipped tenants + tenant_members DDL with a "signup flow
-- handles it" comment, but no auth-app code ever wired the upsert.
-- Discovered during Tier 3.1 PKCE-loopback dogfood (2026-05-15) — prod
-- users including the founder have no tenant_members row, so OAuth
-- authorization_code grants reject with
--   invalid_grant: authorization approval is missing a tenant
-- because lib/handlers/oauth/authorize_route.ts:resolvePrimaryTenantId
-- finds none.
--
-- This function is the atomic primitive auth-app calls on every
-- /api/session POST (login_success + signup_success) and as a defensive
-- fallback in oauth/authorize when an authenticated user still has no
-- membership. PostgREST does not expose multi-statement transactions
-- across REST calls, so the check+insert pair lives here on the server
-- side as one SECURITY DEFINER function.
--
-- Behaviour:
--   - Returns the user's existing primary tenant_id if they already have
--     any (non-deleted) membership.
--   - Otherwise creates a personal tenant + owner membership and returns
--     its tenant_id.
--   - Idempotent — safe to call on every login.
--
-- Concurrency note: two simultaneous calls for the same user could both
-- pass the SELECT and each insert a tenant row. The PRIMARY KEY on
-- tenant_members causes the second membership insert to no-op via ON
-- CONFLICT, but its tenants row would be orphaned (no member). Acceptable
-- — orphan personal tenants can be GC'd by a future job. Login
-- concurrency for the same user is rare in practice.

create or replace function public.ensure_personal_tenant(
  p_user_id uuid,
  p_display_name text
) returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_tenant_id uuid;
begin
  -- Reuse the earliest existing active membership if any.
  select tm.tenant_id into v_tenant_id
  from public.tenant_members tm
  join public.tenants t on t.id = tm.tenant_id and t.deleted_at is null
  where tm.user_id = p_user_id
  order by tm.joined_at asc
  limit 1;

  if v_tenant_id is not null then
    return v_tenant_id;
  end if;

  insert into public.tenants (name, type, plan)
    values (coalesce(nullif(p_display_name, ''), 'Personal'), 'personal', 'free')
    returning id into v_tenant_id;

  insert into public.tenant_members (tenant_id, user_id, role)
    values (v_tenant_id, p_user_id, 'owner')
    on conflict (tenant_id, user_id) do nothing;

  return v_tenant_id;
end;
$$;

-- RLS continues to deny end-user writes to tenants / tenant_members.
-- The function is callable only with the service-role key.
revoke all on function public.ensure_personal_tenant(uuid, text) from public, anon, authenticated;
