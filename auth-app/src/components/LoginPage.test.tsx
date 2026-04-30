import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const signInWithPasswordMock = vi.fn();
const signInWithOAuthMock = vi.fn((provider: 'google') => {
  window.location.href = `https://test.supabase.co/auth/v1/authorize?provider=${provider}`;
});

vi.mock('../lib/supabase', () => ({
  signInWithPassword: signInWithPasswordMock,
  signInWithOAuth: signInWithOAuthMock,
}));

vi.stubEnv('SUPABASE_URL', 'https://test.supabase.co');
vi.stubEnv('SUPABASE_ANON_KEY', 'test-anon-key');
vi.stubEnv('ALLOWED_REDIRECT_ORIGINS', 'https://nexus.bsvibe.dev');

describe('LoginPage - Google OAuth button', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    globalThis.__setMockSearchParams(
      'redirect_uri=https://nexus.bsvibe.dev/callback',
    );
    vi.stubGlobal('fetch', vi.fn());
  });

  it('renders Google sign-in button', async () => {
    const { LoginPage } = await import('./LoginPage');
    render(<LoginPage />);

    expect(screen.getByText(/Continue with Google/i)).toBeInTheDocument();
  });

  it('renders divider between email form and Google button', async () => {
    const { LoginPage } = await import('./LoginPage');
    render(<LoginPage />);

    expect(screen.getByText('or')).toBeInTheDocument();
  });

  it('marks credentials with browser autocomplete hints', async () => {
    const { LoginPage } = await import('./LoginPage');
    render(<LoginPage />);

    expect(screen.getByLabelText('Email')).toHaveAttribute('autoComplete', 'email');
    expect(screen.getByLabelText('Password')).toHaveAttribute('autoComplete', 'current-password');
  });

  it('Google button navigates to Supabase authorize URL on click', async () => {
    const user = userEvent.setup();

    vi.stubGlobal('location', {
      ...window.location,
      origin: 'https://auth.bsvibe.dev',
      href: 'https://auth.bsvibe.dev/login?redirect_uri=https://nexus.bsvibe.dev/callback',
    });

    const { LoginPage } = await import('./LoginPage');
    render(<LoginPage />);

    const googleBtn = screen.getByText(/Continue with Google/i);
    await user.click(googleBtn);

    expect(window.location.href).toContain('supabase.co/auth/v1/authorize');
    expect(window.location.href).toContain('provider=google');
  });

  it('redirects product callbacks with the BSVibe session token returned by /api/session', async () => {
    const user = userEvent.setup();
    signInWithPasswordMock.mockResolvedValue({
      access_token: 'supabase-access-token',
      refresh_token: 'supabase-refresh-token',
      expires_in: 3600,
      token_type: 'bearer',
      user: {
        id: 'user-1',
        email: 'admin@bsvibe.dev',
      },
    });
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: 'bsvibe-session-jwt',
        refresh_token: 'rotated-refresh-token',
        expires_in: 7200,
      }),
    } as Response);

    const { LoginPage } = await import('./LoginPage');
    render(<LoginPage />);

    await user.type(screen.getByLabelText('Email'), 'admin@bsvibe.dev');
    await user.type(screen.getByLabelText('Password'), 'admin1234!');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(fetch).toHaveBeenCalledWith('/api/session', expect.objectContaining({
      method: 'POST',
      credentials: 'same-origin',
      body: JSON.stringify({
        refresh_token: 'supabase-refresh-token',
        event: 'login_success',
        user_id: 'user-1',
        email: 'admin@bsvibe.dev',
      }),
    }));
    expect(window.location.href).toBe(
      'https://nexus.bsvibe.dev/callback#access_token=bsvibe-session-jwt&refresh_token=rotated-refresh-token&expires_in=7200',
    );
    expect(window.location.href).not.toContain('supabase-access-token');
  });
});
