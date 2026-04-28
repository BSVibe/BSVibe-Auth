import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';

vi.stubEnv('SUPABASE_URL', 'https://test.supabase.co');
vi.stubEnv('SUPABASE_ANON_KEY', 'test-anon-key');
vi.stubEnv('ALLOWED_REDIRECT_ORIGINS', 'https://nexus.bsvibe.dev');

describe('SignupPage - Google OAuth button', () => {
  beforeEach(() => {
    globalThis.__setMockSearchParams(
      'redirect_uri=https://nexus.bsvibe.dev/callback',
    );
  });

  it('renders Google sign-up button', async () => {
    const { SignupPage } = await import('./SignupPage');
    render(<SignupPage />);

    expect(screen.getByText(/Sign up with Google/i)).toBeInTheDocument();
  });

  it('renders divider between form and Google button', async () => {
    const { SignupPage } = await import('./SignupPage');
    render(<SignupPage />);

    expect(screen.getByText('or')).toBeInTheDocument();
  });
});
