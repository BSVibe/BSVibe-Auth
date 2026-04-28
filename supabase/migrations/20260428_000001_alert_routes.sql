-- D18 central alert dispatch — runtime-tunable alert routing rules.
--
-- Per BSVibe_Audit_Design.md §11 D-Z2 + BSVibe_Shared_Library_Roadmap.md D18:
--   - alert_routes table lives ONLY in BSVibe-Auth Supabase.
--   - All BSVibe products are dumb clients: they POST audit events to
--     /api/alerts/dispatch and the auth service evaluates the routing rules.
--   - Runtime-editable: `enabled` flips on/off without redeploy; severity /
--     event_pattern / channel config can be tuned through the management
--     endpoints (POST/PATCH/DELETE /api/alerts/rules).
--   - DDL only — no data migration (decision #5: no production users yet).
--
-- Permission model:
--   - core.alerts.read   — list this tenant's rules. Granted to tenant
--                          owners + admins.
--   - core.alerts.manage — create / update / delete rules. Granted to
--                          tenant owners + admins (same set in Phase 0; the
--                          permission name is split so future fine-grained
--                          authz can split them).
--   - alerts.dispatch    — service JWT scope used by `bsvibe-alerts` clients
--                          to POST /api/alerts/dispatch. NOT a row-level
--                          permission — enforced in the handler.
--
-- The endpoints use the auth-app service role to read/write this table, so
-- RLS need only enforce read access via tenant membership. Writes are
-- gated entirely in handler code (the service role bypasses RLS, so the
-- INSERT/UPDATE/DELETE policies below are intentionally restrictive: no
-- end-user JWT can mutate a route directly via PostgREST).

-- ---------------------------------------------------------------------------
-- alert_routes
-- ---------------------------------------------------------------------------
create table if not exists public.alert_routes (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  name text not null,
  -- Glob-style audit event_type pattern, e.g. ``auth.session.failed`` or
  -- ``gateway.*``. Matches the bsvibe-audit AuditAlertRule semantics.
  event_pattern text not null,
  -- Minimum severity at which the rule fires. Mirrors AlertSeverity.
  severity text not null check (severity in ('info', 'warning', 'critical')),
  -- Channel sink. ``structlog`` is the always-on fallback; ``telegram`` and
  -- ``slack`` require the auth-app to hold matching credentials. Future sinks
  -- (webhook / email / discord / bsupervisor / in_app) extend this set.
  channel text not null check (channel in ('telegram', 'slack', 'structlog')),
  -- Channel-specific config (chat_id, webhook URL override, threshold, etc.).
  config jsonb not null default '{}'::jsonb,
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Hot-path index for /api/alerts/dispatch — load every enabled rule for a
-- tenant on every dispatch.
create index if not exists alert_routes_tenant_enabled_idx
  on public.alert_routes (tenant_id, enabled)
  where enabled = true;

-- Secondary index for management UIs that filter by event_pattern.
create index if not exists alert_routes_event_pattern_idx
  on public.alert_routes (event_pattern);

-- updated_at trigger — touch on every UPDATE so admin UIs can show "last
-- changed" without computing.
create or replace function public.alert_routes_touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists alert_routes_touch_updated_at on public.alert_routes;
create trigger alert_routes_touch_updated_at
  before update on public.alert_routes
  for each row
  execute function public.alert_routes_touch_updated_at();

-- ---------------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------------
alter table public.alert_routes enable row level security;

-- SELECT: only members holding ``core.alerts.read`` for this tenant. In
-- Phase 0 we resolve the permission via tenant_members.role (owner/admin),
-- matching the contract used by audit_events. P0.4 will swap this for a
-- ``public.has_permission(uid, tenant_id, perm)`` call without changing
-- the policy surface.
drop policy if exists alert_routes_select_member on public.alert_routes;
create policy alert_routes_select_member on public.alert_routes
  for select
  using (
    exists (
      select 1
      from public.tenant_members tm
      where tm.tenant_id = public.alert_routes.tenant_id
        and tm.user_id = auth.uid()
        and tm.role in ('owner', 'admin')
    )
  );

-- INSERT/UPDATE/DELETE: deny by default (no policy ⇒ RLS denies). End-user
-- JWTs cannot mutate routes via PostgREST. Mutations flow exclusively through
-- /api/alerts/rules{,/[id]} which use the service role and enforce
-- ``core.alerts.manage`` in handler code.

-- ---------------------------------------------------------------------------
-- Comments — operational notes
-- ---------------------------------------------------------------------------
comment on table public.alert_routes is
  'D18 central alert routing. Owned by BSVibe-Auth; all products are dumb clients via POST /api/alerts/dispatch.';
comment on column public.alert_routes.event_pattern is
  'Glob-style audit event_type filter. Trailing `*` and exact equality supported (mirrors bsvibe_audit.alerts).';
comment on column public.alert_routes.severity is
  'Minimum severity ladder: info < warning < critical.';
comment on column public.alert_routes.channel is
  'Sink: structlog (always-on), telegram, slack. Phase A scope.';
comment on column public.alert_routes.config is
  'Channel-specific config — telegram: {chat_id?}, slack: {webhook_url?}, structlog: {}.';
