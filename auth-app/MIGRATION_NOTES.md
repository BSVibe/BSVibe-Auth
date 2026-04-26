# Phase Z Migration Notes — `auth-app` (Vite + React Router → Next.js 15)

This document is the **baseline** for the remaining Phase Z assets
(BSupervisor, BSage, BSGateway, BSNexus, bsvibe-site). Decisions taken here
should be inherited by the others; deviations require justification in the
relevant PR description.

Reference: `~/Docs/BSVibe_Execution_Lockin.md` decisions #8 (Auth = PoC), #9
(RR → next/navigation inline), #10 (Starlight → Nextra 4 — applies to
bsvibe-site only).

---

## 1. Stack Lock-in

| Concern        | Choice                                 | Notes |
|----------------|----------------------------------------|-------|
| Framework      | Next.js 15 App Router                  | `next@^15.0.0` |
| React          | React 19                               | `react@^19.2`, `react-dom@^19.2` |
| CSS            | Tailwind 4 via PostCSS                 | `@tailwindcss/postcss`, `@import "tailwindcss"` in `globals.css` |
| Tests (unit)   | Vitest + Testing Library + jsdom       | `vitest@^4`, `@vitejs/plugin-react@^6` |
| Tests (e2e)    | Playwright                             | `webServer.command: 'next dev -p <port>'` |
| Lint           | ESLint flat config + typescript-eslint | `eslint-config-next` is installed but the existing flat config is kept; the Next plugin warning at build is benign for this app's surface |
| TS             | `~5.9.3`, `moduleResolution: "bundler"`| `paths`: `@/*` mapped to repo root |

`pnpm` is **not** used in `auth-app`. PR #4 confirmed npm is the auth-app
package manager — the lockfile is `package-lock.json`. Other Phase Z assets
should pick the manager that matches their existing repo (most are npm).

---

## 2. Routing — React Router → next/navigation

### Pattern

- `BrowserRouter` / `Routes` / `Route` are deleted. There is no central
  router. Each `app/<route>/page.tsx` is its own entry point.
- `useNavigate` / `useSearchParams` from `react-router-dom`
  → `useRouter` / `useSearchParams` from `next/navigation` **inline at
  the call site** (decision #9 — no compat shim, no helper wrapper).
- `<Link to="...">` (RR) → `<Link href="...">` from `next/link`.
- Programmatic redirect from a Server Component → `redirect()` from
  `next/navigation` (used in `app/page.tsx` to bounce `/` → `/login`).
- Cross-origin redirects (e.g. completing OAuth callback to a product) keep
  `window.location.href = ...` because `next/navigation` is same-origin only.

### Suspense around `useSearchParams`

Next.js 15 requires any client component using `useSearchParams()` to be
wrapped in a `<Suspense>` boundary at its nearest server-component ancestor
or the page becomes opted-in to dynamic-server rendering. We wrap each
client component in `<Suspense fallback={null}>` inside the route page:

```tsx
// app/login/page.tsx
import { Suspense } from 'react';
import { LoginPage } from '@/src/components/LoginPage';
export default function Page() {
  return (
    <Suspense fallback={null}>
      <LoginPage />
    </Suspense>
  );
}
```

### Client/Server boundary

All four pages (login, signup, callback, logout) are interactive and use
hooks → marked `'use client'`. The `app/<route>/page.tsx` files themselves
are server components (zero JS shipped) that import the client component.

---

## 3. API: Vercel `@vercel/node` → Next.js Route Handlers

The handler factories in `api/*.ts` (`createSessionHandler`,
`createSwitchTenantHandler`, `createIssueServiceTokenHandler`, plus the
plain default-export handlers) were **not** rewritten. They keep their
`(req, res)` signature against a local `VercelRequest/VercelResponse`
interface declared in `api/_lib/types.ts` — same shape as `@vercel/node`,
zero dependency.

Why preserve them: the unit tests under `api/**/*.test.ts` use lightweight
`makeReq/makeRes` mocks that mirror that signature. Rewriting the handlers
to native `Request`/`Response` would force a full test rewrite for no
production benefit.

### Adapter pattern (`app/api/_adapter.ts`)

A tiny adapter (~150 LoC) translates `NextRequest` → Vercel-shaped req
and a capturing fake `res` → `Response`. Every Route Handler file is then
a 4-liner:

```ts
// app/api/session/route.ts
import sessionHandler from '@/api/session';
import { vercelToRoute, type VercelStyleHandler } from '@/app/api/_adapter';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const route = vercelToRoute(sessionHandler as unknown as VercelStyleHandler);

export const GET = route;
export const POST = route;
export const DELETE = route;
export const OPTIONS = route;
```

The adapter handles:
- `Content-Type: application/json` body parsing
- form-urlencoded body parsing
- query param flattening (`URLSearchParams` → `Record<string, string>`)
- cookie header parsing into `req.cookies`
- `setHeader('Set-Cookie', ...)` → `Response` headers
- `res.redirect(302, url)` / `res.redirect(url)` → `Location` + 302
- JSON / text / empty bodies

`runtime: 'nodejs'` is explicit because handlers use `Buffer` and other
Node APIs (token decoding via `Buffer.from(..., 'base64url')`).
`dynamic: 'force-dynamic'` prevents Next.js from trying to statically
optimize routes that read cookies/headers.

### When to skip the adapter

For greenfield Next.js handlers in other Phase Z assets that have **no**
existing Vercel-shape tests, write the handler natively against
`(req: NextRequest)` returning `NextResponse.json(...)`. The adapter is a
migration accelerator, not a permanent layer.

---

## 4. Environment Variables

Vite's `import.meta.env.VITE_*` no longer exists. Two prefix conventions:

| Old (Vite)                       | New (Next.js)                                      | Visibility |
|----------------------------------|----------------------------------------------------|------------|
| `VITE_SUPABASE_URL`              | `NEXT_PUBLIC_SUPABASE_URL`                         | client + server (inlined) |
| `VITE_SUPABASE_ANON_KEY`         | `NEXT_PUBLIC_SUPABASE_ANON_KEY`                    | client + server (inlined) |
| `VITE_ALLOWED_REDIRECT_ORIGINS`  | `NEXT_PUBLIC_ALLOWED_REDIRECT_ORIGINS`             | client + server (inlined) |
| `SUPABASE_SERVICE_ROLE_KEY`      | unchanged (server-only)                            | server only |
| `SERVICE_TOKEN_SIGNING_SECRET`   | unchanged (server-only)                            | server only |
| `ALLOWED_REDIRECT_ORIGINS`       | unchanged (server-only — used by route handlers)   | server only |

Library modules accept either prefix at runtime:

```ts
const SUPABASE_URL =
  process.env.NEXT_PUBLIC_SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
```

This dual-read pattern lets vitest stub `SUPABASE_URL` directly (as the
existing tests already do) without churn, and keeps Vercel/production using
the canonical `NEXT_PUBLIC_*` form.

`.env.example` lists both prefixes for the public values plus the
server-only secrets.

---

## 5. Tailwind 4

Tailwind 4 is **config-less** — no `tailwind.config.ts`, no `@tailwind
base/components/utilities` directives. Setup is two files:

```js
// postcss.config.mjs
export default {
  plugins: { '@tailwindcss/postcss': {} },
};
```

```css
/* app/globals.css */
@import "tailwindcss";
/* …existing custom CSS variables and class definitions… */
```

The `auth-app` UI predates Tailwind utility use and ships with hand-rolled
CSS classes (`.container`, `.card`, `.btn`, `.field`, …). Tailwind 4 is
plumbed for new screens to use; existing markup is unchanged.

---

## 6. Test Strategy

### Unit (vitest)

The 9 test files (72 tests) are kept. Frontend tests previously imported
`MemoryRouter` from `react-router-dom` to inject a routing context; that
dependency is gone. Instead, `src/test-setup.ts` mocks `next/navigation`:

```ts
const searchParamsState = { value: new URLSearchParams() };
globalThis.__setMockSearchParams = (init) => {
  searchParamsState.value = typeof init === 'string'
    ? new URLSearchParams(init) : init;
};
vi.mock('next/navigation', () => ({
  useSearchParams: () => searchParamsState.value,
  useRouter: () => ({ push: vi.fn(), /* … */ }),
  usePathname: () => '/',
  redirect: vi.fn(),
}));
vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }) =>
    React.createElement('a', { href, ...rest }, children),
}));
```

Per-test cases call `globalThis.__setMockSearchParams(...)` before
rendering. This is simpler than wiring an in-memory router and matches the
"mock at the seam" testing rule.

API handler tests are unchanged — they call the factory directly with
`makeReq/makeRes`, never touching Next.js internals.

### E2E (playwright)

`playwright.config.ts` boots `next dev -p 5179` (was `vite --port 5179`)
and passes both `NEXT_PUBLIC_*` and unprefixed env vars so client and
server pick the same values. The existing `e2e/auth.spec.ts` is unchanged.

### Vitest config

The deleted `vite.config.ts` is replaced with a thin `vitest.config.ts`
that wires `@vitejs/plugin-react`, jsdom, the `@/*` path alias, and excludes
`.next/` and `e2e/`. Vitest still uses Vite under the hood — only the
production app stops shipping Vite.

---

## 7. Build Output

```
Route (app)                                 Size  First Load JS
┌ ○ /                                      140 B         102 kB
├ ○ /_not-found                            995 B         103 kB
├ ƒ /api/logout                            140 B         102 kB
├ ƒ /api/refresh                           140 B         102 kB
├ ƒ /api/service-tokens/issue              140 B         102 kB
├ ƒ /api/session                           140 B         102 kB
├ ƒ /api/session/switch_tenant             140 B         102 kB
├ ƒ /api/silent-check                      140 B         102 kB
├ ○ /callback                            1.29 kB         107 kB
├ ○ /login                               2.34 kB         108 kB
├ ○ /logout                              1.39 kB         104 kB
└ ○ /signup                              2.44 kB         108 kB
```

Login is 2.3 kB / 108 kB First-Load JS — well within budget for an SSO
landing page. Static prerendering happens for the four user-facing pages;
API routes are dynamic (cookies/headers) as expected.

Smoke-tested locally with `next start`:
- `/login` → 200 HTML
- `/api/session` GET (no cookie) → 401 `{"error":"No session"}`
- `/api/session` POST `{}` → 400
- `/api/session` POST `{"refresh_token":"abc"}` → 200 + `Set-Cookie:
  bsvibe_session=abc; …; Domain=.bsvibe.dev; …`
- `/api/session` OPTIONS → 204 with CORS headers
- `/api/silent-check` (no redirect_uri) → 400
- `/api/refresh` POST `{}` → 400

---

## 8. Vercel Deployment

`vercel.json` is **deleted**. Vercel auto-detects Next.js and sets up
managed infra (no need for explicit `headers` / `rewrites` blocks; the JWKS
proxy is now in `next.config.mjs` `rewrites()`).

The previous CORS headers in `vercel.json` (`/api/(.*)`) are now
per-handler — each route handler's underlying factory sets its own CORS
headers. This is more accurate (different routes have different CORS
needs) and survives the move.

---

## 9. Pitfalls Hit During Migration

These are the gotchas the next 5 assets should anticipate.

1. **`src/pages/` is a Next.js Pages-Router convention.** Even with
   `app/`, Next 15 still scans `src/pages/` and tries to compile every
   `.tsx` file there as a Pages-Router page — including `*.test.tsx` test
   files. The build then chokes on test imports of `vitest`. Solution:
   rename `src/pages/` → `src/components/` (or anything else). This
   migration uses `src/components/`.

2. **`'use client'` plus `useSearchParams()` requires Suspense.**
   Without it, Next.js 15 emits a build-time error and the page falls
   back to dynamic rendering. The pattern: the **page** is a server
   component, it `<Suspense>`-wraps the **component**, and the
   component is `'use client'`.

3. **Removing `@vercel/node`.** The handler factories used
   `import type { VercelRequest, VercelResponse }` purely as a type
   contract — there's no runtime dep. We replaced it with a local
   `api/_lib/types.ts` declaring the same surface. Type narrowing on
   `req.headers.foo` (originally `string | string[]`) was simplified to
   `string | undefined`, which matches the actual single-string runtime
   shape.

4. **`req.body` is `unknown`.** The new types don't pre-coerce JSON
   bodies. Each handler now does `(req.body ?? {}) as { ... }` at the
   destructure site. Same shape as before, explicit cast.

5. **`"type": "module"` in package.json.** Required so `next.config.mjs`,
   `eslint.config.js`, `vitest.config.ts`, `postcss.config.mjs` all parse
   as ES modules. Next.js complains otherwise.

6. **`@testing-library/react` has a peer warning** about `act` not being
   exported from React 19 (a known compat issue across versions). It's a
   warning, not an error; tests pass.

7. **Vitest gets pulled into the Next.js build graph** because the test
   files live under `src/`. The fix is the rename above + Next.js
   automatically excludes `*.test.*` from the App Router (it does not
   from Pages Router).

---

## 10. Inheritance Checklist for Other Phase Z Assets

Before opening the migration PR for BSupervisor / BSage / BSGateway /
BSNexus / bsvibe-site, confirm:

- [ ] `next@^15.0.0`, `react@^19`, `react-dom@^19` in `package.json`
- [ ] `"type": "module"` in `package.json`
- [ ] `app/` (App Router) — not `pages/`
- [ ] No directory named `src/pages/` (use `src/components/` or similar)
- [ ] `tailwind@^4` + `@tailwindcss/postcss` in devDeps; `postcss.config.mjs`
      with the single plugin; `@import "tailwindcss"` in the global CSS
- [ ] Public env vars renamed `VITE_*` → `NEXT_PUBLIC_*`; lib modules
      accept either prefix at runtime to keep tests stable
- [ ] All client components using `useSearchParams()` are wrapped in
      `<Suspense>` at the page-component level
- [ ] React Router → `next/navigation` inline (no compat shim, no helper)
- [ ] Existing Vercel-style API handlers preserved + wrapped via
      `vercelToRoute()` adapter; or rewritten natively if no test surface
      to protect
- [ ] `vercel.json` deleted (Next.js auto-detect handles infra)
- [ ] `vitest.config.ts` (separate from any deleted `vite.config.ts`) with
      `@vitejs/plugin-react`, jsdom, the `@/*` alias, exclude `.next/`
- [ ] `playwright.config.ts` `webServer.command` switched to `next dev`
- [ ] Single PR per repo (append commits, do not open new PRs) per
      execution lockin §4
- [ ] PR description records any lockin deviations

For bsvibe-site specifically: decision #10 specifies Nextra 4 (not bare
Next.js). The pattern in this doc still applies for env vars, Tailwind 4,
and test setup; routing is replaced by Nextra MDX conventions.

---

## 11. Out of Scope (Phase Z PoC)

- The JS SDK (`js/`) — separate package, separate PR (#4 already covers
  that surface).
- Phase 0 P0.4 (Ed25519 + JWKS rotation for service tokens) — still
  HS256-only.
- BSGateway → BSupervisor LLM precheck migration (P0.7) — separate PR.
- Migration of the four product apps — they consume `auth.bsvibe.dev` via
  HTTP, so this Next.js move is invisible to them.
