const SUPABASE_URL = import.meta.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = import.meta.env.SUPABASE_ANON_KEY;

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

interface AuthError {
  error: string;
  error_description: string;
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
    throw new Error(err.error_description || err.error || 'Login failed');
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
    throw new Error(err.error_description || err.error || 'Signup failed');
  }

  return res.json();
}

export function signInWithOAuth(
  provider: 'google',
  opts: { redirectUri: string; state?: string }
): void {
  const callbackUrl = new URL('/callback', window.location.origin);
  callbackUrl.searchParams.set('redirect_uri', opts.redirectUri);
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
