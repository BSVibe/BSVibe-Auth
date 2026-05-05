/**
 * Supabase client wrappers — used by client components.
 *
 * Phase Z: env vars migrated from Vite (`import.meta.env.SUPABASE_*`) to
 * Next.js (`process.env.NEXT_PUBLIC_SUPABASE_*`). Next inlines NEXT_PUBLIC_*
 * at build time, so the values are baked into the client bundle.
 *
 * Vitest stubs `process.env.SUPABASE_URL` / `SUPABASE_ANON_KEY` directly via
 * `vi.stubEnv()`, so we accept either prefix at module init.
 */
const SUPABASE_URL =
  process.env.NEXT_PUBLIC_SUPABASE_URL ?? process.env.SUPABASE_URL ?? '';
const SUPABASE_ANON_KEY =
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? process.env.SUPABASE_ANON_KEY ?? '';

interface AuthResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
  user: {
    id: string;
    email: string;
  };
}

/**
 * Supabase Auth error envelope. Supabase returns at least three
 * distinct shapes depending on the failure mode:
 *
 *   - OAuth/legacy:  ``{ error, error_description }``
 *   - Rate limits:   ``{ code, error_code, msg }``      (e.g.
 *                    ``over_email_send_rate_limit``)
 *   - Newer flows:   ``{ message }`` or ``{ msg }``     (signup
 *                    validation, password policy, etc.)
 *
 * ``humanError`` walks all known fields so the UI never falls back
 * to the generic "Signup failed" / "Login failed" string when
 * Supabase actually told us why.
 */
interface AuthError {
  error?: string;
  error_description?: string;
  error_code?: string;
  msg?: string;
  message?: string;
  code?: number | string;
}

function humanError(err: AuthError, fallback: string): string {
  // The two rate-limit codes are common enough to deserve copy that
  // tells the user what to do, not just what failed.
  if (err.error_code === 'over_email_send_rate_limit') {
    return 'Too many sign-up attempts from this network. Please wait a few minutes and try again, or use Sign in with Google.';
  }
  if (err.error_code === 'over_request_rate_limit') {
    return 'Too many requests. Please wait a moment and try again.';
  }
  return (
    err.error_description ||
    err.msg ||
    err.message ||
    err.error ||
    err.error_code ||
    fallback
  );
}

export async function signInWithPassword(
  email: string,
  password: string
): Promise<AuthResponse> {
  const res = await fetch(
    `${SUPABASE_URL}/auth/v1/token?grant_type=password`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: SUPABASE_ANON_KEY,
      },
      body: JSON.stringify({ email, password }),
    }
  );

  if (!res.ok) {
    const err: AuthError = await res.json();
    throw new Error(humanError(err, 'Login failed'));
  }

  return res.json();
}

export async function signUp(
  email: string,
  password: string
): Promise<AuthResponse> {
  const res = await fetch(`${SUPABASE_URL}/auth/v1/signup`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      apikey: SUPABASE_ANON_KEY,
    },
    body: JSON.stringify({ email, password }),
  });

  if (!res.ok) {
    const err: AuthError = await res.json();
    throw new Error(humanError(err, 'Signup failed'));
  }

  return res.json();
}

export function signInWithOAuth(
  provider: 'google',
  opts: { redirectUri?: string | null; state?: string }
): void {
  const callbackUrl = new URL('/callback', window.location.origin);
  if (opts.redirectUri) {
    callbackUrl.searchParams.set('redirect_uri', opts.redirectUri);
  }
  if (opts.state) {
    callbackUrl.searchParams.set('state', opts.state);
  }

  const authorizeUrl = new URL(`${SUPABASE_URL}/auth/v1/authorize`);
  authorizeUrl.searchParams.set('provider', provider);
  authorizeUrl.searchParams.set('redirect_to', callbackUrl.toString());

  window.location.href = authorizeUrl.toString();
}

export async function signOut(accessToken: string): Promise<void> {
  await fetch(`${SUPABASE_URL}/auth/v1/logout`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      apikey: SUPABASE_ANON_KEY,
      Authorization: `Bearer ${accessToken}`,
    },
  });
}
