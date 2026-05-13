'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { formatDate, type TokenRow } from './tokens-shared';

interface Tenant {
  id: string;
  slug?: string;
  role?: string;
}

interface SessionResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  tenants: Tenant[];
  active_tenant_id: string | null;
}

export function TokensDashboard() {
  const [session, setSession] = useState<SessionResponse | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [tokens, setTokens] = useState<TokenRow[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);

  const reloadList = useCallback(async (accessToken: string) => {
    try {
      const resp = await fetch('/api/tokens', {
        headers: { Authorization: `Bearer ${accessToken}` },
        credentials: 'same-origin',
      });
      if (!resp.ok) {
        setListError(`Failed to load tokens (${resp.status})`);
        return;
      }
      const body = (await resp.json()) as { tokens: TokenRow[] };
      setTokens(body.tokens ?? []);
      setListError(null);
    } catch (err) {
      setListError(err instanceof Error ? err.message : 'Failed to load tokens');
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function bootstrap() {
      try {
        const resp = await fetch('/api/session', {
          method: 'GET',
          credentials: 'same-origin',
        });
        if (resp.status === 401) {
          const dest = encodeURIComponent('/dashboard/tokens');
          window.location.href = `/login?redirect=${dest}`;
          return;
        }
        if (!resp.ok) {
          setSessionError(`Session check failed (${resp.status})`);
          return;
        }
        const body = (await resp.json()) as SessionResponse;
        if (cancelled) return;
        setSession(body);
        await reloadList(body.access_token);
      } catch (err) {
        if (!cancelled) {
          setSessionError(err instanceof Error ? err.message : 'Session check failed');
        }
      }
    }
    bootstrap();
    return () => {
      cancelled = true;
    };
  }, [reloadList]);

  if (sessionError) {
    return (
      <div className="tokens-dashboard">
        <div className="error-box">{sessionError}</div>
      </div>
    );
  }

  if (!session) {
    return (
      <div className="tokens-dashboard">
        <p className="subtitle">Loading…</p>
      </div>
    );
  }

  return (
    <div className="tokens-dashboard">
      <header className="tokens-header">
        <h1>API tokens</h1>
      </header>

      {listError && <div className="error-box">{listError}</div>}

      {tokens === null ? (
        <p className="subtitle">Loading tokens…</p>
      ) : tokens.length === 0 ? (
        <div className="empty-state">
          <p>No API tokens yet.</p>
          <p className="subtitle">
            Sign in to a product CLI (<code>bsgateway login</code>, <code>bsage login</code>, …)
            to mint a personal access token via the device flow.
          </p>
        </div>
      ) : (
        <ul className="tokens-list">
          {tokens.map((t) => (
            <li key={t.id} className="tokens-list-item">
              <div className="tokens-list-main">
                <Link href={`/dashboard/tokens/${t.id}`} className="tokens-list-name">
                  {t.name}
                </Link>
                <div className="tokens-list-meta">
                  <span className="badge">{t.type === 'pat' ? 'PAT' : 'API key'}</span>
                  {t.prefix && <code className="prefix">{t.prefix}</code>}
                  {t.revoked_at && <span className="badge badge-warn">revoked</span>}
                </div>
              </div>
              <div className="tokens-list-detail">
                <div>
                  scopes: {t.scopes.length === 0 ? '—' : t.scopes.join(', ')}
                </div>
                <div>audience: {t.audience.join(', ') || '—'}</div>
                <div>expires: {formatDate(t.expires_at)}</div>
                <div>last used: {formatDate(t.last_used_at)}</div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
