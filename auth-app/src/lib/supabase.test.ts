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
