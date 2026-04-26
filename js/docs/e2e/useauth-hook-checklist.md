# Phase 0 P0.6 — `useAuth()` Hook E2E Checklist

End-to-end behavior verified by P0.5 product integration (BSage / BSGateway / BSupervisor / BSNexus). The js SDK itself is library-only, so library-level e2e collapses to package-shape verification + a manual integration smoke test.

## Package shape

- [x] `npm run build` produces `.d.ts` for `useAuth`, `AuthProvider`, `hasPermission`, `switchTenant`, and the `User` / `Tenant` / `Permission` / `SessionEnvelope` / `SwitchTenantResponse` types.
- [x] `dist/index.d.ts` re-exports all of the above (verified via `cat dist/index.d.ts`).
- [x] `package.json` `peerDependencies.react: >=18.0.0` (optional) — non-React consumers can still import `hasPermission` / `switchTenant` without pulling React.
- [x] No runtime React import inside `permissions.ts` or `switchTenant.ts` (verified — only `useAuth.tsx` imports React).

## Unit-test coverage (proxy for behavioral correctness)

- [x] `permissions.test.ts` — 19 cases covering role × plan × action matrix.
- [x] `switchTenant.test.ts` — 5 cases (happy path, trailing slash, Authorization header, server error, network error).
- [x] `useAuth.test.tsx` — 8 cases (loading → success, fetch options, 401, network error, hasPermission delegation, switchTenant + refresh chain, refresh re-fetch, no-provider throw).
- [x] All 33 tests passing under `vitest` + `jsdom` + `@testing-library/react`.

## Manual integration smoke test (deferred to P0.5)

P0.5 will wire `<AuthProvider>` into one product (likely BSage) and verify the following against `auth.bsvibe.dev` staging:

- [ ] `useAuth()` shows `isLoading=true` on mount, transitions to `isLoading=false` after `/api/session` resolves.
- [ ] When the user has a valid `bsvibe_session` cookie, `user`, `tenants[]`, and `activeTenant` populate from the live envelope.
- [ ] When no cookie / expired cookie, `user` is `null` and `error` is `null` (401 is treated as "not logged in").
- [ ] `hasPermission('bsage.note.write')` returns `true` for an `admin@team` tenant; UX gate (e.g. `<CreateButton>`) renders.
- [ ] `hasPermission('core.tenant.manage')` returns `false` unless role is `owner`.
- [ ] `switchTenant('<other-tenant-id>')` POSTs to `/api/session/switch_tenant`, the response sets the `bsvibe_active_tenant` cookie, and the subsequent `refresh()` returns `active_tenant_id` matching the new tenant.
- [ ] Switching to a non-member tenant id surfaces the auth-app's 403 as a thrown error in `switchTenant`.
- [ ] Cross-origin cookies travel: `Network` panel shows `credentials: include` on both GETs and POSTs to `auth.bsvibe.dev`.
