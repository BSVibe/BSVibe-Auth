'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';

interface TokenRow {
  id: string;
  type: 'pat' | 'api_key';
  prefix: string | null;
  name: string;
  audience: string[];
  scopes: string[];
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
}

interface SessionResponse {
  access_token: string;
}

function formatDate(value: string | null): string {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

export interface TokenDetailPageProps {
  tokenId: string;
}

export function TokenDetailPage({ tokenId }: TokenDetailPageProps) {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [token, setToken] = useState<TokenRow | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function bootstrap() {
      try {
        const sess = await fetch('/api/session', { credentials: 'same-origin' });
        if (sess.status === 401) {
          const dest = encodeURIComponent(`/dashboard/tokens/${tokenId}`);
          window.location.href = `/login?redirect=${dest}`;
          return;
        }
        if (!sess.ok) {
          setError(`Session check failed (${sess.status})`);
          return;
        }
        const sessBody = (await sess.json()) as SessionResponse;
        if (cancelled) return;
        setAccessToken(sessBody.access_token);

        const resp = await fetch(`/api/tokens/${tokenId}`, {
          headers: { Authorization: `Bearer ${sessBody.access_token}` },
          credentials: 'same-origin',
        });
        if (resp.status === 404) {
          setError('Token not found');
          return;
        }
        if (!resp.ok) {
          setError(`Failed to load token (${resp.status})`);
          return;
        }
        const body = (await resp.json()) as { token: TokenRow };
        if (!cancelled) setToken(body.token);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load token');
        }
      }
    }
    bootstrap();
    return () => {
      cancelled = true;
    };
  }, [tokenId]);

  const handleRevoke = useCallback(async () => {
    if (!accessToken || !token) return;
    if (!window.confirm(`Revoke "${token.name}"? This cannot be undone.`)) return;
    setRevoking(true);
    try {
      const resp = await fetch(`/api/tokens/${token.id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${accessToken}` },
        credentials: 'same-origin',
      });
      if (!resp.ok) {
        setError(`Revoke failed (${resp.status})`);
        return;
      }
      const body = (await resp.json()) as { revoked_at: string };
      setToken({ ...token, revoked_at: body.revoked_at });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Revoke failed');
    } finally {
      setRevoking(false);
    }
  }, [accessToken, token]);

  if (error) {
    return (
      <div className="tokens-dashboard">
        <Link href="/dashboard/tokens">← Back to tokens</Link>
        <div className="error-box">{error}</div>
      </div>
    );
  }

  if (!token) {
    return (
      <div className="tokens-dashboard">
        <p className="subtitle">Loading…</p>
      </div>
    );
  }

  return (
    <div className="tokens-dashboard">
      <Link href="/dashboard/tokens">← Back to tokens</Link>
      <header className="tokens-header">
        <h1>{token.name}</h1>
        {!token.revoked_at && (
          <button
            type="button"
            className="btn btn-warn"
            disabled={revoking}
            onClick={handleRevoke}
          >
            {revoking ? 'Revoking…' : 'Revoke'}
          </button>
        )}
      </header>

      <dl className="token-detail">
        <dt>Type</dt>
        <dd>{token.type === 'pat' ? 'Personal access token' : 'API key'}</dd>
        {token.prefix && (
          <>
            <dt>Prefix</dt>
            <dd>
              <code>{token.prefix}</code>
            </dd>
          </>
        )}
        <dt>Scopes</dt>
        <dd>{token.scopes.length === 0 ? '—' : token.scopes.join(', ')}</dd>
        <dt>Audience</dt>
        <dd>{token.audience.length === 0 ? '—' : token.audience.join(', ')}</dd>
        <dt>Created</dt>
        <dd>{formatDate(token.created_at)}</dd>
        <dt>Expires</dt>
        <dd>{formatDate(token.expires_at)}</dd>
        <dt>Last used</dt>
        <dd>{formatDate(token.last_used_at)}</dd>
        {token.revoked_at && (
          <>
            <dt>Revoked at</dt>
            <dd>{formatDate(token.revoked_at)}</dd>
          </>
        )}
      </dl>
    </div>
  );
}
