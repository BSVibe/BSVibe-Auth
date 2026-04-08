import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

vi.stubEnv('SUPABASE_URL', 'https://test.supabase.co');
vi.stubEnv('SUPABASE_ANON_KEY', 'test-anon-key');
vi.stubEnv('ALLOWED_REDIRECT_ORIGINS', 'https://nexus.bsvibe.dev');

describe('LoginPage - Google OAuth button', () => {
  it('renders Google sign-in button', async () => {
    const { LoginPage } = await import('./LoginPage');
    render(
      <MemoryRouter initialEntries={['/login?redirect_uri=https://nexus.bsvibe.dev/callback']}>
        <LoginPage />
      </MemoryRouter>
    );

    expect(screen.getByText(/Continue with Google/i)).toBeInTheDocument();
  });

  it('renders divider between email form and Google button', async () => {
    const { LoginPage } = await import('./LoginPage');
    render(
      <MemoryRouter initialEntries={['/login?redirect_uri=https://nexus.bsvibe.dev/callback']}>
        <LoginPage />
      </MemoryRouter>
    );

    expect(screen.getByText('or')).toBeInTheDocument();
  });

  it('Google button navigates to Supabase authorize URL on click', async () => {
    const user = userEvent.setup();

    vi.stubGlobal('location', {
      ...window.location,
      origin: 'https://auth.bsvibe.dev',
      href: 'https://auth.bsvibe.dev/login?redirect_uri=https://nexus.bsvibe.dev/callback',
    });

    const { LoginPage } = await import('./LoginPage');
    render(
      <MemoryRouter initialEntries={['/login?redirect_uri=https://nexus.bsvibe.dev/callback']}>
        <LoginPage />
      </MemoryRouter>
    );

    const googleBtn = screen.getByText(/Continue with Google/i);
    await user.click(googleBtn);

    expect(window.location.href).toContain('supabase.co/auth/v1/authorize');
    expect(window.location.href).toContain('provider=google');
  });
});
