import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';

vi.stubEnv('ALLOWED_REDIRECT_ORIGINS', 'https://nexus.bsvibe.dev,https://localhost:*');

// Mock fetch for SSO cookie
const fetchMock = vi.fn().mockResolvedValue({ ok: true });
vi.stubGlobal('fetch', fetchMock);

describe('CallbackPage', () => {
  let CallbackPage: typeof import('./CallbackPage').CallbackPage;

  beforeEach(async () => {
    fetchMock.mockClear();
    const mod = await import('./CallbackPage');
    CallbackPage = mod.CallbackPage;
  });

  function renderWithSearch(search: string, hash: string) {
    globalThis.__setMockSearchParams(search.replace(/^\?/, ''));

    // Set hash on window.location since the mock doesn't handle it.
    Object.defineProperty(window, 'location', {
      writable: true,
      value: {
        ...window.location,
        hash,
        href: `https://auth.bsvibe.dev/callback${search}${hash}`,
      },
    });

    return render(<CallbackPage />);
  }

  it('shows error when hash contains error', () => {
    renderWithSearch(
      '?redirect_uri=https://nexus.bsvibe.dev/callback',
      '#error=access_denied&error_description=User+denied+access',
    );

    expect(screen.getByText(/User denied access/)).toBeInTheDocument();
  });

  it('redirects to default when redirect_uri is missing (shared cookie flow)', async () => {
    renderWithSearch(
      '',
      '#access_token=tok&refresh_token=ref&expires_in=3600',
    );

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/session',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ refresh_token: 'ref' }),
        }),
      );
    });

    await waitFor(() => {
      expect(window.location.href).toBe('https://bsvibe.dev/account');
    });
  });

  it('shows error when redirect_uri is not allowed', async () => {
    renderWithSearch(
      '?redirect_uri=https://evil.com/callback',
      '#access_token=tok&refresh_token=ref&expires_in=3600',
    );

    await waitFor(() => {
      expect(screen.getByText(/not allowed/i)).toBeInTheDocument();
    });
  });

  it('sets SSO cookie and redirects on valid tokens', async () => {
    const assignMock = vi.fn();
    Object.defineProperty(window, 'location', {
      writable: true,
      value: {
        ...window.location,
        hash: '#access_token=tok&refresh_token=ref&expires_in=3600',
        href: 'https://auth.bsvibe.dev/callback?redirect_uri=https://nexus.bsvibe.dev/callback&state=s1#access_token=tok&refresh_token=ref&expires_in=3600',
        assign: assignMock,
      },
    });
    globalThis.__setMockSearchParams(
      'redirect_uri=https://nexus.bsvibe.dev/callback&state=s1',
    );

    render(<CallbackPage />);

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/session',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ refresh_token: 'ref' }),
        }),
      );
    });

    await waitFor(() => {
      expect(window.location.href).toContain('nexus.bsvibe.dev/callback#');
      expect(window.location.href).toContain('access_token=tok');
    });
  });

  it('shows processing state', () => {
    renderWithSearch(
      '?redirect_uri=https://nexus.bsvibe.dev/callback',
      '#access_token=tok&refresh_token=ref&expires_in=3600',
    );

    expect(screen.getByText('BSVibe')).toBeInTheDocument();
  });
});
