# BSVibe-Auth (auth-app)

`auth.bsvibe.dev` — the BSVibe SSO surface. Issues Supabase-backed user sessions,
manages tenant context (`switch_tenant`), and mints scoped service JWTs
(`/api/service-tokens/issue`) used by BSGateway / BSage / BSupervisor / BSNexus.

## Stack

- **Next.js 15** App Router (`app/`)
- **React 19**
- **Tailwind 4** via `@tailwindcss/postcss` + `@import "tailwindcss"`
- **Supabase** (auth + RLS + tenant tables)
- **Vitest** for unit tests, **Playwright** for e2e

This app was migrated from Vite + React Router in Phase Z. See
[`MIGRATION_NOTES.md`](./MIGRATION_NOTES.md) for the full transition record —
that document is the baseline pattern the remaining 5 Phase Z assets follow.

## Layout

```
auth-app/
├─ app/                       # Next.js 15 App Router
│  ├─ layout.tsx
│  ├─ page.tsx                # → redirects to /login
│  ├─ globals.css             # Tailwind 4 + dark theme
│  ├─ login/page.tsx          # thin Suspense wrappers around src/components/*
│  ├─ signup/page.tsx
│  ├─ callback/page.tsx
│  ├─ logout/page.tsx
│  └─ api/                    # Next.js Route Handlers
│     ├─ _adapter.ts          # Vercel-style → Route-Handler adapter
│     ├─ session/route.ts
│     ├─ session/switch_tenant/route.ts
│     ├─ refresh/route.ts
│     ├─ logout/route.ts
│     ├─ silent-check/route.ts
│     └─ service-tokens/issue/route.ts
├─ api/                       # Vercel-style handler factories (unit-tested)
│  ├─ _lib/{tenants,service-token,test-helpers,types}.ts
│  ├─ session.ts              # createSessionHandler() + default
│  ├─ session/switch_tenant.ts
│  ├─ refresh.ts
│  ├─ logout.ts
│  ├─ silent-check.ts
│  └─ service-tokens/issue.ts
├─ src/
│  ├─ components/             # client React components (LoginPage, ...)
│  ├─ lib/{supabase,redirect}.ts
│  └─ test-setup.ts           # vitest setup — mocks next/navigation, next/link
├─ e2e/auth.spec.ts
├─ next.config.mjs
├─ postcss.config.mjs
├─ vitest.config.ts
├─ playwright.config.ts
└─ tsconfig.json
```

## Scripts

```bash
npm run dev       # next dev -p 5179
npm run build     # next build
npm start         # next start
npm test          # vitest run (unit)
npm run test:e2e  # playwright (boots `next dev` on 5179)
npm run lint      # eslint .
```

## Environment

See `.env.example`. Two prefix conventions:

- `NEXT_PUBLIC_*` — inlined into the client bundle at build time
  (`NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`,
  `NEXT_PUBLIC_ALLOWED_REDIRECT_ORIGINS`).
- Unprefixed — server-only, available to Route Handlers and never sent to the
  client (`SUPABASE_SERVICE_ROLE_KEY`, `SERVICE_TOKEN_SIGNING_SECRET`,
  `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `ALLOWED_REDIRECT_ORIGINS`).

For local development with mock values, the unprefixed forms also serve as
fallbacks for the public ones — the lib modules accept either at runtime.
