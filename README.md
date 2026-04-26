# BSVibe-Auth

Centralized authentication for the BSVibe ecosystem.

`auth.bsvibe.dev` provides a hosted login/signup UI and JWT-based SSO for all
BSVibe products. Consumer apps integrate via the JavaScript SDK (frontend) or
the Python package (FastAPI backends).

## Structure

```
BSVibe-Auth/
├── auth-app/   ← React SPA + Vercel API endpoints (auth.bsvibe.dev)
├── js/         ← @bsvibe/auth — TypeScript SDK for frontend apps
└── python/     ← bsvibe-auth — JWT verification for FastAPI backends
```

## auth-app

React 19 + Vite SPA deployed to Vercel as `auth.bsvibe.dev`. Hosts the login,
signup, logout, and OAuth callback pages, plus serverless API endpoints for
SSO session management.

**Features**
- Email/password authentication via Supabase
- Google OAuth via Supabase authorize flow
- SSO via 1st-party `bsvibe_session` cookie (HttpOnly, 30 days)
- Redirect-based silent check (no iframes — Chrome 3rd-party cookie safe)
- BSVibe dark design system (Plus Jakarta Sans, indigo accent, CSS variable tokens)

**Routes**
| Path | Purpose |
|------|---------|
| `/login` | Email/password + Google sign-in |
| `/signup` | Account creation |
| `/logout` | Clear session and redirect |
| `/callback` | OAuth redirect handler |

**API endpoints**
| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/session` | Set SSO cookie from `refresh_token` |
| `GET` | `/api/session` | Refresh tokens + return `tenants[]` and `active_tenant_id` |
| `DELETE` | `/api/session` | Clear session cookie |
| `POST` | `/api/session/switch_tenant` | Set active tenant (validates membership) |
| `POST` | `/api/service-tokens/issue` | Issue audience-scoped service JWT (admin/owner only) |
| `POST` | `/api/refresh` | Token refresh |
| `POST` | `/api/logout` | Invalidate Supabase session |
| `GET` | `/api/silent-check` | SSO probe via redirect |

**Development**
```bash
cd auth-app
npm install
cp .env.example .env  # Set SUPABASE_URL, SUPABASE_ANON_KEY, ALLOWED_REDIRECT_ORIGINS
npm run dev           # http://localhost:5173
npm test              # Vitest unit tests
npm run test:e2e      # Playwright E2E tests
npm run build
```

## @bsvibe/auth (JavaScript SDK)

TypeScript SDK for frontend apps that need to integrate with `auth.bsvibe.dev`.
Published to GitHub Packages.

```bash
npm install @bsvibe/auth
```

```typescript
import { BSVibeAuth } from '@bsvibe/auth';

const auth = new BSVibeAuth({
  authUrl: 'https://auth.bsvibe.dev',
});

// On app load
const user = await auth.checkSession();
if (user === 'redirect') {
  auth.redirectToLogin();
}

// Token for API calls
const token = auth.getToken();
```

See [js/README.md](js/README.md) for full API.

## bsvibe-auth (Python)

JWT verification package for FastAPI backends. Validates Supabase-issued
tokens (ES256 via JWKS, or HS256 with shared secret) and exposes a
`BSVibeUser` model.

```bash
pip install git+https://github.com/BSVibe/BSVibe-Auth.git#subdirectory=python
```

```python
from fastapi import FastAPI, Depends
from bsvibe_auth import BsvibeAuthProvider, BSVibeUser
from bsvibe_auth.fastapi import create_get_current_user

auth = BsvibeAuthProvider(auth_url="https://auth.bsvibe.dev")
get_current_user = create_get_current_user(auth)

app = FastAPI()

@app.get("/me")
async def me(user: BSVibeUser = Depends(get_current_user)) -> dict:
    return {"id": user.id, "email": user.email}
```

See [python/README.md](python/README.md) for full API.

## Architecture

```
┌─────────────────┐         ┌──────────────────┐
│  Consumer app   │  login  │ auth.bsvibe.dev  │
│  (nexus, etc.)  │ ──────► │   (auth-app)     │
│                 │         │                  │
│  @bsvibe/auth   │ ◄────── │  Supabase Auth   │
└─────────────────┘ tokens  └──────────────────┘
        │
        │ JWT
        ▼
┌─────────────────┐
│ FastAPI backend │
│  bsvibe-auth    │  ← verifies token via JWKS
└─────────────────┘
```

Consumer apps redirect to `auth.bsvibe.dev/login?redirect_uri=...`. After
sign-in, tokens are returned in the URL hash fragment. The SDK stores them in
localStorage, and the SSO cookie enables silent check on subsequent visits.

## CI

GitHub Actions runs on every PR ([.github/workflows/ci.yml](.github/workflows/ci.yml)):
- **auth-app**: lint, vitest, build, Playwright E2E
- **js-sdk**: build
- **python**: pytest

## License

TBD
