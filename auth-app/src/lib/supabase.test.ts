import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock import.meta.env before importing the module
vi.stubEnv('SUPABASE_URL', 'https://test.supabase.co');
vi.stubEnv('SUPABASE_ANON_KEY', 'test-anon-key');

describe('signInWithOAuth', () => {
  let signInWithOAuth: typeof import('./supabase').signInWithOAuth;

  beforeEach(async () => {
    vi.stubGlobal('location', {
      ...window.location,
      origin: 'https://auth.bsvibe.dev',
      href: 'https://auth.bsvibe.dev/login',
    });

    // Dynamic import to get the mocked version
    const mod = await import('./supabase');
    signInWithOAuth = mod.signInWithOAuth;
  });

  it('redirects to Supabase authorize URL with correct params', () => {
    signInWithOAuth('google', {
      redirectUri: 'https://nexus.bsvibe.dev/callback',
      state: 'abc123',
    });

    const url = new URL(window.location.href);
    expect(url.origin).toBe('https://test.supabase.co');
    expect(url.pathname).toBe('/auth/v1/authorize');
    expect(url.searchParams.get('provider')).toBe('google');

    const redirectTo = new URL(url.searchParams.get('redirect_to')!);
    expect(redirectTo.origin).toBe('https://auth.bsvibe.dev');
    expect(redirectTo.pathname).toBe('/callback');
    expect(redirectTo.searchParams.get('redirect_uri')).toBe(
      'https://nexus.bsvibe.dev/callback'
    );
    expect(redirectTo.searchParams.get('state')).toBe('abc123');
  });

  it('omits state param when not provided', () => {
    signInWithOAuth('google', {
      redirectUri: 'https://nexus.bsvibe.dev/callback',
    });

    const url = new URL(window.location.href);
    const redirectTo = new URL(url.searchParams.get('redirect_to')!);
    expect(redirectTo.searchParams.has('state')).toBe(false);
  });
});

describe('signUp / signInWithPassword error envelopes', () => {
  let signUp: typeof import('./supabase').signUp;
  let signInWithPassword: typeof import('./supabase').signInWithPassword;

  beforeEach(async () => {
    const mod = await import('./supabase');
    signUp = mod.signUp;
    signInWithPassword = mod.signInWithPassword;
  });

  function mockFetchOnce(status: number, body: unknown): void {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValueOnce({
        ok: status >= 200 && status < 300,
        status,
        json: vi.fn().mockResolvedValue(body),
      }),
    );
  }

  it('signUp surfaces over_email_send_rate_limit as friendly copy', async () => {
    // Real production response shape — captured via Playwright probe
    // 2026-05-04: ``{ code: 429, error_code, msg }``.
    mockFetchOnce(429, {
      code: 429,
      error_code: 'over_email_send_rate_limit',
      msg: 'email rate limit exceeded',
    });

    await expect(signUp('a@example.com', 'pw12345678')).rejects.toThrow(
      /Too many sign-up attempts/i,
    );
  });

  it('signUp surfaces over_request_rate_limit with friendly copy', async () => {
    mockFetchOnce(429, {
      code: 429,
      error_code: 'over_request_rate_limit',
      msg: 'request rate limit exceeded',
    });

    await expect(signUp('a@example.com', 'pw12345678')).rejects.toThrow(
      /Too many requests/i,
    );
  });

  it('signUp falls back to msg field when error_description absent', async () => {
    mockFetchOnce(400, {
      code: 400,
      error_code: 'weak_password',
      msg: 'Password must contain at least one digit',
    });

    await expect(signUp('a@example.com', 'pw12345678')).rejects.toThrow(
      /Password must contain at least one digit/,
    );
  });

  it('signUp preserves legacy error_description when present', async () => {
    mockFetchOnce(400, {
      error: 'invalid_grant',
      error_description: 'Email already registered',
    });

    await expect(signUp('a@example.com', 'pw12345678')).rejects.toThrow(
      'Email already registered',
    );
  });

  it('signInWithPassword surfaces invalid_credentials with msg fallback', async () => {
    mockFetchOnce(400, {
      code: 400,
      error_code: 'invalid_credentials',
      msg: 'Invalid login credentials',
    });

    await expect(
      signInWithPassword('a@example.com', 'wrongpw'),
    ).rejects.toThrow('Invalid login credentials');
  });

  it('falls back to fixed string when no error fields present', async () => {
    mockFetchOnce(500, {});
    await expect(signUp('a@example.com', 'pw12345678')).rejects.toThrow(
      'Signup failed',
    );
  });
});
