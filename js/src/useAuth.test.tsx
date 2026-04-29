import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { useAuth, AuthProvider } from './useAuth';
import type { ReactNode } from 'react';

const VALID_SESSION = {
  user: { id: 'u1', email: 'alice@example.com', name: 'Alice' },
  tenants: [
    { id: 't1', name: 'Alice Personal', type: 'personal', role: 'owner', plan: 'pro' },
    { id: 't2', name: 'ACME', type: 'org', role: 'admin', plan: 'team' },
  ],
  active_tenant_id: 't2',
  access_token: 'tok',
  refresh_token: 'ref',
  expires_in: 900,
};

function makeFetchMock(initialResponses: Array<unknown>) {
  const responses = [...initialResponses];
  return vi.fn().mockImplementation(() => {
    const next = responses.shift();
    if (next === undefined) {
      return Promise.resolve({ ok: false, status: 500, json: async () => ({ error: 'no more mocks' }) });
    }
    return Promise.resolve({
      ok: true,
      status: 200,
      json: async () => next,
    });
  });
}

function wrapper(authUrl: string, fetchImpl: typeof fetch) {
  return ({ children }: { children: ReactNode }) => (
    <AuthProvider authUrl={authUrl} fetchImpl={fetchImpl}>
      {children}
    </AuthProvider>
  );
}

describe('useAuth', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('starts in loading state and resolves to user + tenants from /api/session', async () => {
    const fetchMock = makeFetchMock([VALID_SESSION]);

    const { result } = renderHook(() => useAuth(), {
      wrapper: wrapper('https://auth.bsvibe.dev', fetchMock as unknown as typeof fetch),
    });

    expect(result.current.isLoading).toBe(true);

    await waitFor(() => expect(result.current.isLoading).toBe(false));

    expect(result.current.user).toEqual(VALID_SESSION.user);
    expect(result.current.tenants).toHaveLength(2);
    expect(result.current.activeTenant?.id).toBe('t2');
    expect(result.current.error).toBeNull();
  });

  it('GETs /api/session with credentials: include for SSO cookie', async () => {
    const fetchMock = makeFetchMock([VALID_SESSION]);

    renderHook(() => useAuth(), {
      wrapper: wrapper('https://auth.bsvibe.dev', fetchMock as unknown as typeof fetch),
    });

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://auth.bsvibe.dev/api/session');
    expect(init.method ?? 'GET').toBe('GET');
    expect(init.credentials).toBe('include');
  });

  it('returns user=null and no error when /api/session returns 401', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: 'No session' }),
    });

    const { result } = renderHook(() => useAuth(), {
      wrapper: wrapper('https://auth.bsvibe.dev', fetchMock as unknown as typeof fetch),
    });

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.user).toBeNull();
    expect(result.current.activeTenant).toBeNull();
    expect(result.current.tenants).toEqual([]);
    expect(result.current.error).toBeNull();
  });

  it('captures error when fetch itself rejects', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('boom'));

    const { result } = renderHook(() => useAuth(), {
      wrapper: wrapper('https://auth.bsvibe.dev', fetchMock as unknown as typeof fetch),
    });

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.user).toBeNull();
    expect(result.current.error?.message).toBe('boom');
  });

  it('hasPermission delegates to client helper using activeTenant', async () => {
    const fetchMock = makeFetchMock([VALID_SESSION]);

    const { result } = renderHook(() => useAuth(), {
      wrapper: wrapper('https://auth.bsvibe.dev', fetchMock as unknown as typeof fetch),
    });

    await waitFor(() => expect(result.current.isLoading).toBe(false));

    // t2 = admin / team plan
    expect(result.current.hasPermission('bsage.note.write')).toBe(true);
    expect(result.current.hasPermission('core.member.invite')).toBe(true);
    expect(result.current.hasPermission('core.tenant.manage')).toBe(false);
  });

  it('switchTenant POSTs and refreshes session', async () => {
    const SWITCHED_SESSION = {
      ...VALID_SESSION,
      active_tenant_id: 't1',
    };
    const fetchMock = makeFetchMock([
      VALID_SESSION,                            // initial GET /api/session
      { active_tenant_id: 't1', role: 'owner' }, // POST /api/session/switch_tenant
      SWITCHED_SESSION,                          // refresh GET /api/session
    ]);

    const { result } = renderHook(() => useAuth(), {
      wrapper: wrapper('https://auth.bsvibe.dev', fetchMock as unknown as typeof fetch),
    });

    await waitFor(() => expect(result.current.activeTenant?.id).toBe('t2'));

    await act(async () => {
      await result.current.switchTenant('t1');
    });

    await waitFor(() => expect(result.current.activeTenant?.id).toBe('t1'));

    // Verify the POST was made
    const switchCall = fetchMock.mock.calls.find(
      (c) => typeof c[0] === 'string' && c[0].includes('switch_tenant'),
    );
    expect(switchCall).toBeDefined();
    expect(switchCall![1].method).toBe('POST');
    expect(switchCall![1].body).toBe(JSON.stringify({ tenant_id: 't1' }));
  });

  it('refresh() re-fetches /api/session', async () => {
    const fetchMock = makeFetchMock([
      VALID_SESSION,
      { ...VALID_SESSION, user: { ...VALID_SESSION.user, name: 'Alice 2' } },
    ]);

    const { result } = renderHook(() => useAuth(), {
      wrapper: wrapper('https://auth.bsvibe.dev', fetchMock as unknown as typeof fetch),
    });

    await waitFor(() => expect(result.current.user?.name).toBe('Alice'));

    await act(async () => {
      await result.current.refresh();
    });

    await waitFor(() => expect(result.current.user?.name).toBe('Alice 2'));
  });

  it('throws if useAuth is called outside AuthProvider', () => {
    // suppress error log noise for this expected throw
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => renderHook(() => useAuth())).toThrow(/AuthProvider/);
    errSpy.mockRestore();
  });
});
