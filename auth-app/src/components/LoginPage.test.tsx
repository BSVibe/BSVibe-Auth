import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

vi.stubEnv('SUPABASE_URL', 'https://test.supabase.co');
vi.stubEnv('SUPABASE_ANON_KEY', 'test-anon-key');
vi.stubEnv('ALLOWED_REDIRECT_ORIGINS', 'https://nexus.bsvibe.dev');

describe('LoginPage - Google OAuth button', () => {
  beforeEach(() => {
    globalThis.__setMockSearchParams(
      'redirect_uri=https://nexus.bsvibe.dev/callback',
    );
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
});
