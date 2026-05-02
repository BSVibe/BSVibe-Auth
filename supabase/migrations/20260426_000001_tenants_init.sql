-- Phase 0 P0.2 — tenants + tenant_members + RLS
--
-- Decision #5 (project plan): no data migration in this PR — there are no
-- production users yet, so we only ship CREATE TABLE / POLICY DDL. Any
-- backfill (e.g. provisioning a personal tenant per existing auth.users row)
-- is out of scope.
--
-- Tables live in the `public` schema and reference `auth.users` so RLS can
-- match `auth.uid()` directly.

-- ---------------------------------------------------------------------------
-- tenants
-- ---------------------------------------------------------------------------
create table if not exists public.tenants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  type text not null check (type in ('personal', 'org')),
  plan text not null default 'free' check (plan in ('free', 'pro', 'team', 'enterprise')),
  created_at timestamptz not null default now(),
  deleted_at timestamptz
);

create index if not exists tenants_active_idx
  on public.tenants (id)
  where deleted_at is null;

-- ---------------------------------------------------------------------------
-- tenant_members
-- ---------------------------------------------------------------------------
create table if not exists public.tenant_members (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner', 'admin', 'member', 'viewer')),
  joined_at timestamptz not null default now(),
  primary key (tenant_id, user_id)
);

create index if not exists tenant_members_user_idx
  on public.tenant_members (user_id);

-- ---------------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------------
alter table public.tenants enable row level security;
alter table public.tenant_members enable row level security;

-- tenants: a row is visible to a user only if they are a member.
drop policy if exists tenants_select_member on public.tenants;
create policy tenants_select_member on public.tenants
  for select
  using (
    exists (
      select 1 from public.tenant_members tm
      where tm.tenant_id = public.tenants.id
        and tm.user_id = auth.uid()
    )
  );

-- tenant_members: a user can see their own membership row, plus all
-- membership rows for any tenant they belong to (so the org admin sees
-- their teammates).
drop policy if exists tenant_members_select_self on public.tenant_members;
create policy tenant_members_select_self on public.tenant_members
  for select
  using (
    user_id = auth.uid()
    or exists (
      select 1 from public.tenant_members self
      where self.tenant_id = public.tenant_members.tenant_id
        and self.user_id = auth.uid()
    )
  );

-- Inserts/updates/deletes are handled exclusively via the auth-app service
-- role (signup flow, switch_tenant, admin actions). End-user JWTs MUST NOT
-- be able to mutate tenants / tenant_members directly — no permissive write
-- policies are defined here, so RLS denies by default.
