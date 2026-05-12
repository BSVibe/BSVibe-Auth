import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';

vi.stubEnv('SUPABASE_URL', 'https://test.supabase.co');
vi.stubEnv('SUPABASE_ANON_KEY', 'test-anon-key');

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
    const resp = typeof route === 'function' ? route(init) : route;
    return resp as unknown as Response;
  });
}

const TENANT = '11111111-1111-1111-1111-111111111111';
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

describe('TokensDashboard', () => {
  it('redirects to /login when /api/session returns 401', async () => {
    const hrefSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      value: {
        ...window.location,
        get href() {
          return 'https://auth.bsvibe.dev/dashboard/tokens';
        },
        set href(v: string) {
          hrefSpy(v);
        },
      },
      configurable: true,
    });

    const fetchMock = makeFetchMock({
      'GET /api/session': jsonResponse({ error: 'No session' }, 401),
    });
    vi.stubGlobal('fetch', fetchMock);

    const { TokensDashboard } = await import('./TokensDashboard');
    render(<TokensDashboard />);

    await waitFor(() => {
      expect(hrefSpy).toHaveBeenCalledWith(expect.stringContaining('/login'));
    });
  });

  it('renders empty state with device-flow hint when no tokens exist', async () => {
    const fetchMock = makeFetchMock({
      'GET /api/session': SESSION_OK,
      'GET /api/tokens': jsonResponse({ tokens: [] }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const { TokensDashboard } = await import('./TokensDashboard');
    render(<TokensDashboard />);

    expect(await screen.findByText(/no api tokens yet/i)).toBeInTheDocument();
    expect(screen.getByText(/bsgateway login/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /new token/i })).not.toBeInTheDocument();
  });

  it('lists tokens returned by /api/tokens', async () => {
    const fetchMock = makeFetchMock({
      'GET /api/session': SESSION_OK,
      'GET /api/tokens': jsonResponse({
        tokens: [
          {
            id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            type: 'api_key',
            name: 'CLI key',
            prefix: 'bsv_sk_xxxx',
            audience: ['gateway'],
            scopes: ['gateway:models:read'],
            created_at: '2026-05-07T00:00:00Z',
            expires_at: '2026-08-05T00:00:00Z',
            last_used_at: null,
            revoked_at: null,
          },
        ],
      }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const { TokensDashboard } = await import('./TokensDashboard');
    render(<TokensDashboard />);

    expect(await screen.findByText('CLI key')).toBeInTheDocument();
    expect(screen.getByText(/bsv_sk_xxxx/)).toBeInTheDocument();
  });
});
