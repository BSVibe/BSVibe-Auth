-- Production bootstrap seed.
--
-- Idempotent: safe to re-run. Applied via the Supabase Deploy workflow with
-- `workflow_dispatch` + `include_seed=true`, NOT on every migration push, so
-- accidental data drift is unlikely.
--
-- Why this exists: the auth-app `/api/session` handler returns
-- `active_tenant_id: null` for any user without a `tenant_members` row. Until
-- the Phase 3 tenant-management UI lands, prod admins need at least one
-- tenant pre-provisioned so frontends boot into a usable workspace.

-- Bootstrap tenant for admin@bsvibe.dev (user_id from prod auth.users).
do $$
declare
  admin_uid constant uuid := '67a49e60-8882-4a38-a544-4efa7c7f9d5a';
  bootstrap_tenant_id uuid;
begin
  -- Skip entirely if the admin user is missing (e.g. running this seed
  -- against a fresh project — let migrations land first, then create users).
  if not exists (select 1 from auth.users where id = admin_uid) then
    raise notice 'admin user % not found — skipping bootstrap seed', admin_uid;
    return;
  end if;

  -- If admin already belongs to any tenant, nothing to do.
  if exists (select 1 from public.tenant_members where user_id = admin_uid) then
    raise notice 'admin already has tenant membership — skipping';
    return;
  end if;

  insert into public.tenants (name, type, plan)
  values ('BSVibe Admin', 'personal', 'team')
  returning id into bootstrap_tenant_id;

  insert into public.tenant_members (tenant_id, user_id, role)
  values (bootstrap_tenant_id, admin_uid, 'owner');

  raise notice 'bootstrapped tenant % for admin %', bootstrap_tenant_id, admin_uid;
end $$;
