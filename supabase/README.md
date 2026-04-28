# Supabase migrations

Schema for the BSVibe-Auth Supabase project.

## Files

| File | Purpose |
|------|---------|
| `migrations/20260426_000001_tenants_init.sql` | Phase 0 P0.2 — `tenants`, `tenant_members`, RLS |

## Applying

There is no data migration in Phase 0 (decision #5 — no production users yet).
The DDL is intentionally idempotent (`create ... if not exists`,
`drop policy if exists`) so it can be re-applied safely.

### Supabase CLI

```bash
supabase db push --db-url "$SUPABASE_DB_URL"
```

### Manual (SQL editor)

Open the Supabase project SQL editor, paste the contents of each file in
chronological order, and run.

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
