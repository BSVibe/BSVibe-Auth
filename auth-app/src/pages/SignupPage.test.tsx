import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

vi.stubEnv('SUPABASE_URL', 'https://test.supabase.co');
vi.stubEnv('SUPABASE_ANON_KEY', 'test-anon-key');
vi.stubEnv('ALLOWED_REDIRECT_ORIGINS', 'https://nexus.bsvibe.dev');

describe('SignupPage - Google OAuth button', () => {
  it('renders Google sign-up button', async () => {
    const { SignupPage } = await import('./SignupPage');
    render(
      <MemoryRouter initialEntries={['/signup?redirect_uri=https://nexus.bsvibe.dev/callback']}>
        <SignupPage />
      </MemoryRouter>
    );

    expect(screen.getByText(/Sign up with Google/i)).toBeInTheDocument();
  });

  it('renders divider between form and Google button', async () => {
    const { SignupPage } = await import('./SignupPage');
    render(
      <MemoryRouter initialEntries={['/signup?redirect_uri=https://nexus.bsvibe.dev/callback']}>
        <SignupPage />
      </MemoryRouter>
    );

    expect(screen.getByText('or')).toBeInTheDocument();
  });
});
