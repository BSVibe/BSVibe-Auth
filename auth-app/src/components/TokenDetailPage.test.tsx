import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

vi.stubEnv('SUPABASE_URL', 'https://test.supabase.co');
vi.stubEnv('SUPABASE_ANON_KEY', 'test-anon-key');

const TOKEN_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const TENANT = '11111111-1111-1111-1111-111111111111';

interface MockResponse {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}

function jsonResponse(body: unknown, status = 200): MockResponse {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

function makeFetchMock(routes: Record<string, MockResponse | ((init?: RequestInit) => MockResponse)>) {
  return vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    const key = `${method} ${url}`;
    const route = routes[key] ?? routes[url];
    if (!route) {
      throw new Error(`Unmocked fetch: ${key}`);
    }
    return (typeof route === 'function' ? route(init) : route) as unknown as Response;
  });
}

const SESSION_OK = jsonResponse({
  access_token: 'sb-access-token',
  refresh_token: '',
  expires_in: 3600,
  tenants: [{ id: TENANT, slug: 'acme', role: 'admin' }],
  active_tenant_id: TENANT,
});

beforeEach(() => {
  vi.clearAllMocks();
  globalThis.__setMockSearchParams('');
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('TokenDetailPage', () => {
  it('shows token metadata and allows revoking an active token', async () => {
    const fetchMock = makeFetchMock({
      'GET /api/session': SESSION_OK,
      [`GET /api/tokens/${TOKEN_ID}`]: jsonResponse({
        token: {
          id: TOKEN_ID,
          type: 'api_key',
          prefix: 'bsv_sk_xxxx',
          name: 'CLI key',
          audience: ['gateway'],
          scopes: ['gateway:models:read'],
          created_at: '2026-05-07T00:00:00Z',
          expires_at: '2026-08-05T00:00:00Z',
          last_used_at: '2026-05-07T01:23:00Z',
          revoked_at: null,
        },
      }),
      [`DELETE /api/tokens/${TOKEN_ID}`]: jsonResponse({
        id: TOKEN_ID,
        revoked_at: '2026-05-07T02:00:00Z',
        already_revoked: false,
      }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const user = userEvent.setup();
    const { TokenDetailPage } = await import('./TokenDetailPage');
    render(<TokenDetailPage tokenId={TOKEN_ID} />);

    expect(await screen.findByText('CLI key')).toBeInTheDocument();
    expect(screen.getByText(/bsv_sk_xxxx/)).toBeInTheDocument();
    expect(screen.getByText(/gateway:models:read/)).toBeInTheDocument();

    // confirm() is clicked through; stub it to return true
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
    await user.click(screen.getByRole('button', { name: /revoke/i }));
    confirmSpy.mockRestore();

    await waitFor(() => {
      expect(screen.getByText(/revoked at/i)).toBeInTheDocument();
    });
    // Revoke button no longer visible after revocation
    expect(screen.queryByRole('button', { name: /^revoke$/i })).not.toBeInTheDocument();
  });

  it('renders 404 message when token is not found', async () => {
    const fetchMock = makeFetchMock({
      'GET /api/session': SESSION_OK,
      [`GET /api/tokens/${TOKEN_ID}`]: jsonResponse({ error: 'Token not found' }, 404),
    });
    vi.stubGlobal('fetch', fetchMock);

    const { TokenDetailPage } = await import('./TokenDetailPage');
    render(<TokenDetailPage tokenId={TOKEN_ID} />);

    expect(await screen.findByText(/token not found/i)).toBeInTheDocument();
  });
});
