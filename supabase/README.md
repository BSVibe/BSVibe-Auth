# Supabase migrations

Schema for the BSVibe-Auth Supabase project.

## Files

| File | Purpose |
|------|---------|
| `migrations/20260426_000001_tenants_init.sql` | Phase 0 P0.2 — `tenants`, `tenant_members`, RLS |
| `migrations/20260427_000001_audit_schema.sql` | Audit Phase 1 — `audit_events`, query/ingest views |
| `migrations/20260428_000001_alert_routes.sql` | D18 — central alert dispatch routes |
| `seed.sql` | Idempotent prod bootstrap (admin tenant) — workflow_dispatch only |

## Applying

**Migrations apply automatically** via `.github/workflows/supabase-deploy.yml`
on every merge to `main` that touches `supabase/migrations/**`. Adding a new
migration file IS the deploy.

The DDL is intentionally idempotent (`create ... if not exists`,
`drop policy if exists`) so re-runs are safe.

### Required GitHub repo secrets

| Secret | Source |
|--------|--------|
| `SUPABASE_ACCESS_TOKEN` | https://supabase.com/dashboard/account/tokens |
| `SUPABASE_DB_PASSWORD`  | Project Settings → Database → DB Password |

(Project ref `hobuqhkrqqhuvpxofdcc` is hardcoded in the workflow so a wrong
secret can never silently retarget the deploy.)

### Manual (rare — only when CI broken)

```bash
cd supabase
supabase link --project-ref hobuqhkrqqhuvpxofdcc
supabase db push --include-all
```

Or paste each `migrations/*.sql` into the Supabase Dashboard SQL Editor in
chronological order.

## History

Pre-2026-05-03: migrations were applied **manually** per the original Phase 0
note "no production users yet." That step was forgotten across multiple PRs
and `tenants` / `audit_events` / `alert_routes` were never created in prod —
silently breaking tenant resolution because `/api/session` swallows the
missing-table error and returns `active_tenant_id: null`. The
`supabase-deploy.yml` workflow was added so the manual step can never be
forgotten again.

## Tables

### `public.tenants`

| Column | Type | Notes |
|--------|------|-------|
| `id` | `uuid` PK | `gen_random_uuid()` default |
| `name` | `text` | Display name |
| `type` | `text` | `personal` or `org` |
| `plan` | `text` | `free` \| `pro` \| `team` \| `enterprise` (default `free`) |
| `created_at` | `timestamptz` | default `now()` |
| `deleted_at` | `timestamptz` | soft-delete marker |

### `public.tenant_members`

| Column | Type | Notes |
|--------|------|-------|
| `tenant_id` | `uuid` FK → `tenants.id` (cascade) | |
| `user_id` | `uuid` FK → `auth.users.id` (cascade) | |
| `role` | `text` | `owner` \| `admin` \| `member` \| `viewer` |
| `joined_at` | `timestamptz` | default `now()` |
| **PK** | `(tenant_id, user_id)` | |

## RLS policies

- `tenants` — `SELECT` allowed when `auth.uid()` exists in
  `tenant_members` for that tenant. No `INSERT/UPDATE/DELETE` policies →
  end-user JWTs cannot mutate. Service role bypasses RLS.
- `tenant_members` — `SELECT` allowed for self rows (so a user sees their
  own membership) and for any row in a tenant they belong to (so org admins
  see teammates). No write policies — service role only.
