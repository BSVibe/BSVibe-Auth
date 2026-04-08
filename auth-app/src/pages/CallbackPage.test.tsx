import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

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

  function renderWithRouter(search: string, hash: string) {
    // Set hash on window.location since MemoryRouter doesn't handle hash
    Object.defineProperty(window, 'location', {
      writable: true,
      value: {
        ...window.location,
        hash,
        href: `https://auth.bsvibe.dev/callback${search}${hash}`,
      },
    });

    return render(
      <MemoryRouter initialEntries={[`/callback${search}`]}>
        <CallbackPage />
      </MemoryRouter>
    );
  }

  it('shows error when hash contains error', () => {
    renderWithRouter(
      '?redirect_uri=https://nexus.bsvibe.dev/callback',
      '#error=access_denied&error_description=User+denied+access'
    );

    expect(screen.getByText(/User denied access/)).toBeInTheDocument();
  });

  it('shows error when redirect_uri is missing', () => {
    renderWithRouter(
      '',
      '#access_token=tok&refresh_token=ref&expires_in=3600'
    );

    expect(screen.getByText(/Missing redirect_uri/i)).toBeInTheDocument();
  });

  it('shows error when redirect_uri is not allowed', () => {
    renderWithRouter(
      '?redirect_uri=https://evil.com/callback',
      '#access_token=tok&refresh_token=ref&expires_in=3600'
    );

    expect(screen.getByText(/not allowed/i)).toBeInTheDocument();
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

    render(
      <MemoryRouter initialEntries={['/callback?redirect_uri=https://nexus.bsvibe.dev/callback&state=s1']}>
        <CallbackPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/api/session', expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ refresh_token: 'ref' }),
      }));
    });

    await waitFor(() => {
      // Should redirect to callback URL with tokens in hash
      expect(window.location.href).toContain('nexus.bsvibe.dev/callback#');
      expect(window.location.href).toContain('access_token=tok');
    });
  });

  it('shows processing state', () => {
    renderWithRouter(
      '?redirect_uri=https://nexus.bsvibe.dev/callback',
      '#access_token=tok&refresh_token=ref&expires_in=3600'
    );

    expect(screen.getByText('BSVibe')).toBeInTheDocument();
  });
});
