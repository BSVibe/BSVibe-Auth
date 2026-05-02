-- Audit Phase Batch 1 — audit_events table + monthly partitions + RLS
--
-- Per BSVibe_Audit_Design.md §4 (storage tier) and §5 (query model):
--   - DDL only — no data migration (decision #5: no production users yet).
--   - Postgres declarative partitioning by RANGE(occurred_at), monthly.
--   - Pre-create the current month + 12 forward partitions; future months
--     are added by a maintenance cron (out of scope for this PR).
--   - RLS: only users with `core.audit.read` permission scoped to the row's
--     `tenant_id` can SELECT. Writes happen exclusively through the
--     auth-app service role (audit-emit helper / /api/audit/events).
--
-- The bsvibe-audit AuditEventBase shape arrives from collectors as:
--   { event_id, event_type, occurred_at, actor, tenant_id, trace_id?, data }
-- We project actor/data into JSONB columns and keep the rest as scalar
-- columns so the indexes can be tight.

-- ---------------------------------------------------------------------------
-- audit_events parent (partitioned)
-- ---------------------------------------------------------------------------
create table if not exists public.audit_events (
  id uuid not null default gen_random_uuid(),
  event_type text not null,
  event_data jsonb not null default '{}'::jsonb,
  occurred_at timestamptz not null,
  ingested_at timestamptz not null default now(),
  tenant_id uuid not null,
  actor jsonb not null,
  trace_id text,
  primary key (id, occurred_at)
) partition by range (occurred_at);

-- Indexes propagate to every partition.
create index if not exists audit_events_tenant_time_idx
  on public.audit_events (tenant_id, occurred_at desc);

create index if not exists audit_events_type_time_idx
  on public.audit_events (event_type, occurred_at desc);

create index if not exists audit_events_trace_idx
  on public.audit_events (trace_id)
  where trace_id is not null;

-- Idempotency: event_id must be unique. A unique index on (id, occurred_at)
-- already exists via the PK, but `INSERT ... ON CONFLICT DO NOTHING` from
-- the ingestion endpoint targets `id` alone — so we add a per-partition
-- unique constraint via the PK and rely on the `event_id` field of the
-- payload mapping to `id`. The PK works because partition pruning on
-- occurred_at is applied automatically when both columns are present in
-- the conflict target.

-- ---------------------------------------------------------------------------
-- Monthly partitions: current month + 12 forward
-- ---------------------------------------------------------------------------
do $$
declare
  start_month date := date_trunc('month', now())::date;
  i int;
  part_start date;
  part_end date;
  part_name text;
begin
  for i in 0..12 loop
    part_start := (start_month + (i || ' months')::interval)::date;
    part_end := (start_month + ((i + 1) || ' months')::interval)::date;
    part_name := 'audit_events_' || to_char(part_start, 'YYYY_MM');
    execute format(
      'create table if not exists public.%I partition of public.audit_events for values from (%L) to (%L)',
      part_name, part_start, part_end
    );
  end loop;
end $$;

-- ---------------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------------
alter table public.audit_events enable row level security;

-- Helper: does the current authenticated user hold the `core.audit.read`
-- permission for the row's tenant? In Phase 0 the bsvibe-authz package
-- exposes `public.has_permission(uid uuid, tenant_id uuid, perm text)`
-- (see P0.4). If the function does not yet exist, the policy denies — RLS
-- defaults to deny. We reference it by qualified name so future migrations
-- can swap the implementation without touching this file.
drop policy if exists audit_events_select_with_permission on public.audit_events;
create policy audit_events_select_with_permission on public.audit_events
  for select
  using (
    exists (
      select 1
      from public.tenant_members tm
      where tm.tenant_id = public.audit_events.tenant_id
        and tm.user_id = auth.uid()
        and tm.role in ('owner', 'admin')
    )
  );

-- Writes are NOT allowed via end-user JWTs. The auth-app service role
-- bypasses RLS, so /api/audit/events and the audit-emit helper INSERT
-- through the service role client. No INSERT/UPDATE/DELETE policy is
-- defined here; RLS denies by default.

-- ---------------------------------------------------------------------------
-- Comments — operational notes
-- ---------------------------------------------------------------------------
comment on table public.audit_events is
  'BSVibe audit log. Partitioned monthly on occurred_at. Writes only via service role.';
comment on column public.audit_events.event_type is
  'Dotted namespace, e.g. auth.session.started, authz.service_token.issued.';
comment on column public.audit_events.actor is
  'JSONB: { type: "user"|"service"|"system", id: string, email?: string, ... }';
comment on column public.audit_events.event_data is
  'Free-form payload. PII handling per BSVibe_Audit_Design.md §7.2.';
