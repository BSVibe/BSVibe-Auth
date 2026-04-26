import { describe, it, expect, beforeEach, vi } from 'vitest';
import { switchTenant } from './switchTenant';

describe('switchTenant', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('POSTs tenant_id to /api/session/switch_tenant on the configured authUrl', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ active_tenant_id: 't2', role: 'admin' }),
    });

    const result = await switchTenant({
      authUrl: 'https://auth.bsvibe.dev',
      tenantId: 't2',
      fetchImpl: fetchMock,
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://auth.bsvibe.dev/api/session/switch_tenant');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('include');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(init.body).toBe(JSON.stringify({ tenant_id: 't2' }));
    expect(result).toEqual({ active_tenant_id: 't2', role: 'admin' });
  });

  it('strips trailing slashes from authUrl', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ active_tenant_id: 't2', role: 'owner' }),
    });

    await switchTenant({
      authUrl: 'https://auth.bsvibe.dev///',
      tenantId: 't2',
      fetchImpl: fetchMock,
    });

    expect(fetchMock.mock.calls[0][0]).toBe('https://auth.bsvibe.dev/api/session/switch_tenant');
  });

  it('forwards Authorization header when accessToken provided', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ active_tenant_id: 't2', role: 'admin' }),
    });

    await switchTenant({
      authUrl: 'https://auth.bsvibe.dev',
      tenantId: 't2',
      accessToken: 'tok-abc',
      fetchImpl: fetchMock,
    });

    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe('Bearer tok-abc');
  });

  it('throws on non-2xx response with error code', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      json: async () => ({ error: 'Not a member of the requested tenant' }),
    });

    await expect(
      switchTenant({
        authUrl: 'https://auth.bsvibe.dev',
        tenantId: 't-other',
        fetchImpl: fetchMock,
      }),
    ).rejects.toThrow(/Not a member/);
  });

  it('throws when fetch itself rejects', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error('network down'));

    await expect(
      switchTenant({
        authUrl: 'https://auth.bsvibe.dev',
        tenantId: 't2',
        fetchImpl: fetchMock,
      }),
    ).rejects.toThrow('network down');
  });
});
