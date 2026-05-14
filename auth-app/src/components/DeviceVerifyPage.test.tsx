import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

vi.stubEnv('SUPABASE_URL', 'https://test.supabase.co');
vi.stubEnv('SUPABASE_ANON_KEY', 'test-anon-key');

const TENANT = '11111111-1111-1111-1111-111111111111';
const USER_CODE = 'ABCD-1234';

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

function makeFetchMock(
  routes: Record<
    string,
    MockResponse | ((init?: RequestInit) => MockResponse)
  >,
) {
  return vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    const exact = `${method} ${url}`;
    // Exact match first, then prefix-style match for query-string routes.
    let route = routes[exact] ?? routes[url];
    if (!route) {
      const prefixKey = Object.keys(routes).find((k) => {
        const sep = k.indexOf(' ');
        if (sep === -1) return false;
        const m = k.slice(0, sep);
        const u = k.slice(sep + 1);
        return m === method && url.startsWith(u);
      });
      if (prefixKey) route = routes[prefixKey];
    }
    if (!route) {
      throw new Error(`Unmocked fetch: ${exact}`);
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

const LOOKUP_OK = jsonResponse({
  user_code: USER_CODE,
  client_id: 'cli-tool',
  scope: ['bsgateway:models:read'],
  audience: ['bsgateway'],
  expires_at: '2099-01-01T00:00:00Z',
});

beforeEach(() => {
  vi.clearAllMocks();
  globalThis.__setMockSearchParams(`user_code=${USER_CODE}`);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('DeviceVerifyPage', () => {
  it('renders the user_code, scopes/audience, and posts approve', async () => {
    const verifyMock = vi.fn(() => jsonResponse({ status: 'approved' }));
    const fetchMock = makeFetchMock({
      'GET /api/session': SESSION_OK,
      'GET /api/oauth/device/lookup': LOOKUP_OK,
      'POST /api/oauth/device/verify': verifyMock,
    });
    vi.stubGlobal('fetch', fetchMock);

    const user = userEvent.setup();
    const { DeviceVerifyPage } = await import('./DeviceVerifyPage');
    render(<DeviceVerifyPage />);

    expect(
      await screen.findByText(/device is requesting access/i),
    ).toBeInTheDocument();
    expect(screen.getByText(USER_CODE)).toBeInTheDocument();

    // Scopes + audience must be visible so the user can decide.
    expect(await screen.findByText('bsgateway:models:read')).toBeInTheDocument();
    expect(screen.getByText('cli-tool')).toBeInTheDocument();
    expect(screen.getByText('bsgateway')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /^approve$/i }));

    await waitFor(() => {
      expect(verifyMock).toHaveBeenCalledTimes(1);
    });

    const verifyCall = fetchMock.mock.calls.find(
      ([url, init]) =>
        typeof url === 'string' &&
        url === '/api/oauth/device/verify' &&
        (init?.method ?? 'GET').toUpperCase() === 'POST',
    );
    expect(verifyCall).toBeDefined();
    const init = verifyCall?.[1] as RequestInit;
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body).toEqual({ user_code: USER_CODE, action: 'approve' });
    expect(init.headers).toMatchObject({
      Authorization: 'Bearer sb-access-token',
      'Content-Type': 'application/json',
    });

    expect(await screen.findByText(/approved/i)).toBeInTheDocument();
  });

  it('posts deny when the user clicks Deny', async () => {
    const verifyMock = vi.fn(() => jsonResponse({ status: 'denied' }));
    const fetchMock = makeFetchMock({
      'GET /api/session': SESSION_OK,
      'GET /api/oauth/device/lookup': LOOKUP_OK,
      'POST /api/oauth/device/verify': verifyMock,
    });
    vi.stubGlobal('fetch', fetchMock);

    const user = userEvent.setup();
    const { DeviceVerifyPage } = await import('./DeviceVerifyPage');
    render(<DeviceVerifyPage />);

    await user.click(await screen.findByRole('button', { name: /^deny$/i }));

    await waitFor(() => {
      expect(verifyMock).toHaveBeenCalledTimes(1);
    });
    const denyCall = fetchMock.mock.calls.find(
      ([url, init]) =>
        typeof url === 'string' &&
        url === '/api/oauth/device/verify' &&
        (init?.method ?? 'GET').toUpperCase() === 'POST',
    );
    expect(denyCall).toBeDefined();
    const init = denyCall?.[1] as RequestInit;
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body).toEqual({ user_code: USER_CODE, action: 'deny' });
    expect(await screen.findByText(/denied/i)).toBeInTheDocument();
  });

  it('redirects to /login when the session check returns 401', async () => {
    const fetchMock = makeFetchMock({
      'GET /api/session': jsonResponse({ error: 'unauthorized' }, 401),
    });
    vi.stubGlobal('fetch', fetchMock);
    const hrefSetter = vi.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: {
        get href() {
          return '';
        },
        set href(value: string) {
          hrefSetter(value);
        },
      },
    });

    const { DeviceVerifyPage } = await import('./DeviceVerifyPage');
    render(<DeviceVerifyPage />);

    await waitFor(() => {
      expect(hrefSetter).toHaveBeenCalledTimes(1);
    });
    const dest = hrefSetter.mock.calls[0][0] as string;
    expect(dest).toContain('/login?redirect=');
    expect(decodeURIComponent(dest.split('redirect=')[1])).toBe(
      `/oauth/device/verify?user_code=${USER_CODE}`,
    );
  });

  it('shows an error when the user_code is missing', async () => {
    globalThis.__setMockSearchParams('');
    const fetchMock = makeFetchMock({
      'GET /api/session': SESSION_OK,
    });
    vi.stubGlobal('fetch', fetchMock);

    const { DeviceVerifyPage } = await import('./DeviceVerifyPage');
    render(<DeviceVerifyPage />);

    expect(
      await screen.findByText(/missing user_code/i),
    ).toBeInTheDocument();
  });

  it('still allows approve/deny when the lookup endpoint fails', async () => {
    const verifyMock = vi.fn(() => jsonResponse({ status: 'approved' }));
    const fetchMock = makeFetchMock({
      'GET /api/session': SESSION_OK,
      'GET /api/oauth/device/lookup': jsonResponse(
        { error: 'user_code not found, expired, or already verified' },
        404,
      ),
      'POST /api/oauth/device/verify': verifyMock,
    });
    vi.stubGlobal('fetch', fetchMock);

    const user = userEvent.setup();
    const { DeviceVerifyPage } = await import('./DeviceVerifyPage');
    render(<DeviceVerifyPage />);

    // Lookup error is rendered inline so the user knows details are unverified.
    expect(
      await screen.findByText(/not found, expired, or already verified/i),
    ).toBeInTheDocument();

    // But the approve/deny path still works — the user is the source of truth.
    await user.click(screen.getByRole('button', { name: /^approve$/i }));
    await waitFor(() => {
      expect(verifyMock).toHaveBeenCalledTimes(1);
    });
  });

  it('shows server error inline when verify fails', async () => {
    const fetchMock = makeFetchMock({
      'GET /api/session': SESSION_OK,
      'GET /api/oauth/device/lookup': LOOKUP_OK,
      'POST /api/oauth/device/verify': jsonResponse(
        { error: 'user_code not found, expired, or already verified' },
        404,
      ),
    });
    vi.stubGlobal('fetch', fetchMock);

    const user = userEvent.setup();
    const { DeviceVerifyPage } = await import('./DeviceVerifyPage');
    render(<DeviceVerifyPage />);

    await user.click(await screen.findByRole('button', { name: /^approve$/i }));

    expect(
      await screen.findByText(/not found, expired, or already verified/i),
    ).toBeInTheDocument();
  });
});
