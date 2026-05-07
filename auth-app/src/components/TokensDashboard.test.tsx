import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

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
  // jsdom provides a navigator.clipboard but it's read-only. Stub once.
  Object.defineProperty(globalThis.navigator, 'clipboard', {
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
    configurable: true,
  });
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

  it('renders empty state when no tokens exist', async () => {
    const fetchMock = makeFetchMock({
      'GET /api/session': SESSION_OK,
      'GET /api/tokens': jsonResponse({ tokens: [] }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const { TokensDashboard } = await import('./TokensDashboard');
    render(<TokensDashboard />);

    expect(await screen.findByText(/no api tokens yet/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /new token/i })).toBeInTheDocument();
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

  it('opens the create modal when "New token" is clicked', async () => {
    const fetchMock = makeFetchMock({
      'GET /api/session': SESSION_OK,
      'GET /api/tokens': jsonResponse({ tokens: [] }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const user = userEvent.setup();
    const { TokensDashboard } = await import('./TokensDashboard');
    render(<TokensDashboard />);

    await screen.findByText(/no api tokens yet/i);
    await user.click(screen.getByRole('button', { name: /new token/i }));

    expect(screen.getByRole('dialog', { name: /create token/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/name/i)).toBeInTheDocument();
  });

  it('creates an api_key, shows the raw token once, and requires acknowledgement to dismiss', async () => {
    let listCalls = 0;
    const fetchMock = makeFetchMock({
      'GET /api/session': SESSION_OK,
      'GET /api/tokens': () => {
        listCalls += 1;
        return jsonResponse({ tokens: [] });
      },
      'POST /api/tokens': (init) => {
        const body = init?.body ? JSON.parse(init.body as string) : {};
        expect(body.type).toBe('api_key');
        expect(body.name).toBe('My CLI');
        expect(body.tenant_id).toBe(TENANT);
        expect(body.scopes).toEqual(['gateway:models:read']);
        expect(body.audience).toEqual(['gateway']);
        return jsonResponse(
          {
            id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            type: 'api_key',
            name: 'My CLI',
            prefix: 'bsv_sk_aaaa',
            scopes: ['gateway:models:read'],
            audience: ['gateway'],
            expires_at: '2026-08-05T00:00:00Z',
            token: 'bsv_sk_RAW_SECRET_VALUE_xxxxxxxxxxxxxxxxxxxxxx',
          },
          201,
        );
      },
    });
    vi.stubGlobal('fetch', fetchMock);

    const user = userEvent.setup();
    const { TokensDashboard } = await import('./TokensDashboard');
    render(<TokensDashboard />);

    await screen.findByText(/no api tokens yet/i);
    expect(listCalls).toBe(1);

    await user.click(screen.getByRole('button', { name: /new token/i }));

    const dialog = screen.getByRole('dialog', { name: /create token/i });
    await user.type(within(dialog).getByLabelText(/name/i), 'My CLI');
    await user.click(within(dialog).getByLabelText(/api key/i));
    await user.click(within(dialog).getByLabelText(/gateway:models:read/));
    await user.click(within(dialog).getByLabelText(/^BSGateway$/));

    await user.click(within(dialog).getByRole('button', { name: /create token/i }));

    // Raw secret modal appears
    const secretDialog = await screen.findByRole('dialog', { name: /save your token/i });
    expect(within(secretDialog).getByText(/bsv_sk_RAW_SECRET_VALUE/)).toBeInTheDocument();

    // Dismiss is disabled until acknowledged
    const dismiss = within(secretDialog).getByRole('button', { name: /^done$/i });
    expect(dismiss).toBeDisabled();

    await user.click(
      within(secretDialog).getByLabelText(/i have copied/i),
    );
    expect(dismiss).not.toBeDisabled();

    await user.click(dismiss);

    // Raw token must not remain on the page after dismiss
    await waitFor(() =>
      expect(screen.queryByText(/bsv_sk_RAW_SECRET_VALUE/)).not.toBeInTheDocument(),
    );

    // List is re-fetched
    await waitFor(() => expect(listCalls).toBeGreaterThanOrEqual(2));
  });

  it('shows raw access_token + refresh_token for PAT creation', async () => {
    const fetchMock = makeFetchMock({
      'GET /api/session': SESSION_OK,
      'GET /api/tokens': jsonResponse({ tokens: [] }),
      'POST /api/tokens': jsonResponse(
        {
          id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
          type: 'pat',
          name: 'PAT thing',
          scopes: ['gateway:models:read'],
          audience: ['gateway'],
          expires_at: '2026-05-07T01:00:00Z',
          access_token: 'eyJ.access.token',
          refresh_token: 'rt-secret-value',
          token_type: 'Bearer',
          expires_in: 3600,
        },
        201,
      ),
    });
    vi.stubGlobal('fetch', fetchMock);

    const user = userEvent.setup();
    const { TokensDashboard } = await import('./TokensDashboard');
    render(<TokensDashboard />);

    await screen.findByText(/no api tokens yet/i);
    await user.click(screen.getByRole('button', { name: /new token/i }));

    const dialog = screen.getByRole('dialog', { name: /create token/i });
    await user.type(within(dialog).getByLabelText(/name/i), 'PAT thing');
    // PAT is the default selection, but click defensively
    await user.click(within(dialog).getByLabelText(/personal access/i));
    await user.click(within(dialog).getByLabelText(/gateway:models:read/));
    await user.click(within(dialog).getByLabelText(/^BSGateway$/));
    await user.click(within(dialog).getByRole('button', { name: /create token/i }));

    const secretDialog = await screen.findByRole('dialog', { name: /save your token/i });
    expect(within(secretDialog).getByText(/eyJ\.access\.token/)).toBeInTheDocument();
    expect(within(secretDialog).getByText(/rt-secret-value/)).toBeInTheDocument();
  });
});
