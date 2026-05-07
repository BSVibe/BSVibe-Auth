'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  AUDIENCE_CATALOG,
  EXPIRY_CATALOG,
  SCOPE_CATALOG,
} from '../../lib/scopes-catalog';
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

interface CreateApiKeyResponse {
  id: string;
  type: 'api_key';
  name: string;
  prefix: string;
  scopes: string[];
  audience: string[];
  expires_at: string;
  token: string;
}

interface CreatePatResponse {
  id: string;
  type: 'pat';
  name: string;
  scopes: string[];
  audience: string[];
  expires_at: string;
  access_token: string;
  refresh_token: string;
  token_type: 'Bearer';
  expires_in: number;
}

type CreateResponse = CreateApiKeyResponse | CreatePatResponse;

interface RawSecretState {
  type: 'pat' | 'api_key';
  name: string;
  // For api_key: { token }; for pat: { access_token, refresh_token }
  apiKey?: string;
  accessToken?: string;
  refreshToken?: string;
}

export function TokensDashboard() {
  const [session, setSession] = useState<SessionResponse | null>(null);
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [tokens, setTokens] = useState<TokenRow[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [rawSecret, setRawSecret] = useState<RawSecretState | null>(null);

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
          // Bounce to login, preserving where we wanted to go.
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

  const onCreated = useCallback(
    async (raw: RawSecretState) => {
      setShowCreate(false);
      setRawSecret(raw);
      if (session) {
        await reloadList(session.access_token);
      }
    },
    [reloadList, session],
  );

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
        <button
          type="button"
          className="btn"
          onClick={() => setShowCreate(true)}
        >
          New token
        </button>
      </header>

      {listError && <div className="error-box">{listError}</div>}

      {tokens === null ? (
        <p className="subtitle">Loading tokens…</p>
      ) : tokens.length === 0 ? (
        <div className="empty-state">
          <p>No API tokens yet.</p>
          <p className="subtitle">
            Create a personal access token (PAT) or an API key to call BSVibe APIs.
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

      {showCreate && (
        <CreateTokenModal
          accessToken={session.access_token}
          tenantId={session.active_tenant_id}
          tenants={session.tenants}
          onCancel={() => setShowCreate(false)}
          onCreated={onCreated}
        />
      )}

      {rawSecret && (
        <RawSecretModal
          state={rawSecret}
          onDismiss={() => setRawSecret(null)}
        />
      )}
    </div>
  );
}

interface CreateTokenModalProps {
  accessToken: string;
  tenantId: string | null;
  tenants: Tenant[];
  onCancel: () => void;
  onCreated: (raw: RawSecretState) => Promise<void>;
}

function CreateTokenModal(props: CreateTokenModalProps) {
  const [type, setType] = useState<'pat' | 'api_key'>('pat');
  const [name, setName] = useState('');
  const [tenantId, setTenantId] = useState<string>(props.tenantId ?? '');
  const [scopes, setScopes] = useState<string[]>([]);
  const [audience, setAudience] = useState<string[]>([]);
  const [expiresIn, setExpiresIn] = useState<number>(0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const tenantOptions = props.tenants ?? [];
  const canSubmit = useMemo(
    () =>
      !submitting &&
      name.trim().length > 0 &&
      tenantId.length > 0 &&
      scopes.length > 0 &&
      audience.length > 0,
    [submitting, name, tenantId, scopes.length, audience.length],
  );

  const toggle = (
    list: string[],
    value: string,
    setter: (next: string[]) => void,
  ) => {
    setter(list.includes(value) ? list.filter((v) => v !== value) : [...list, value]);
  };

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {
        type,
        name: name.trim(),
        tenant_id: tenantId,
        scopes,
        audience,
      };
      if (expiresIn > 0) {
        body.expires_in_s = expiresIn;
      }
      const resp = await fetch('/api/tokens', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${props.accessToken}`,
        },
        credentials: 'same-origin',
        body: JSON.stringify(body),
      });
      if (!resp.ok) {
        const errBody = (await resp.json().catch(() => ({}))) as { error?: string };
        setError(errBody.error || `Create failed (${resp.status})`);
        return;
      }
      const created = (await resp.json()) as CreateResponse;
      const raw: RawSecretState =
        created.type === 'api_key'
          ? { type: 'api_key', name: created.name, apiKey: created.token }
          : {
              type: 'pat',
              name: created.name,
              accessToken: created.access_token,
              refreshToken: created.refresh_token,
            };
      await props.onCreated(raw);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Create failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Create token"
      className="modal-overlay"
    >
      <form className="modal-card" onSubmit={handleSubmit}>
        <h2>Create token</h2>
        {error && <div className="error-box">{error}</div>}

        <fieldset className="field">
          <legend>Type</legend>
          <label>
            <input
              type="radio"
              name="token-type"
              value="pat"
              checked={type === 'pat'}
              onChange={() => setType('pat')}
            />
            Personal access token (PAT)
          </label>
          <label>
            <input
              type="radio"
              name="token-type"
              value="api_key"
              checked={type === 'api_key'}
              onChange={() => setType('api_key')}
            />
            API key
          </label>
        </fieldset>

        <div className="field">
          <label htmlFor="token-name">Name</label>
          <input
            id="token-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={128}
            placeholder="e.g. CLI laptop"
            required
          />
        </div>

        {tenantOptions.length > 1 && (
          <div className="field">
            <label htmlFor="token-tenant">Tenant</label>
            <select
              id="token-tenant"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
            >
              {tenantOptions.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.slug ?? t.id}
                </option>
              ))}
            </select>
          </div>
        )}

        <fieldset className="field">
          <legend>Scopes</legend>
          {SCOPE_CATALOG.map((s) => (
            <label key={s.value} className="check-row">
              <input
                type="checkbox"
                aria-label={s.label}
                checked={scopes.includes(s.value)}
                onChange={() => toggle(scopes, s.value, setScopes)}
              />
              <span>
                <code>{s.label}</code>
                <span className="check-row-desc">{s.description}</span>
              </span>
            </label>
          ))}
        </fieldset>

        <fieldset className="field">
          <legend>Audience</legend>
          {AUDIENCE_CATALOG.map((a) => (
            <label key={a.value} className="check-row">
              <input
                type="checkbox"
                aria-label={a.label}
                checked={audience.includes(a.value)}
                onChange={() => toggle(audience, a.value, setAudience)}
              />
              <span>
                {a.label}
                <span className="check-row-desc">{a.description}</span>
              </span>
            </label>
          ))}
        </fieldset>

        <div className="field">
          <label htmlFor="token-expiry">Expires</label>
          <select
            id="token-expiry"
            value={expiresIn}
            onChange={(e) => setExpiresIn(Number(e.target.value))}
          >
            {EXPIRY_CATALOG.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        <div className="modal-actions">
          <button type="button" className="btn btn-ghost" onClick={props.onCancel}>
            Cancel
          </button>
          <button type="submit" className="btn" disabled={!canSubmit}>
            {submitting ? 'Creating…' : 'Create token'}
          </button>
        </div>
      </form>
    </div>
  );
}

interface RawSecretModalProps {
  state: RawSecretState;
  onDismiss: () => void;
}

function RawSecretModal({ state, onDismiss }: RawSecretModalProps) {
  const [acked, setAcked] = useState(false);

  async function copy(value: string) {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      // Best-effort. Some browsers reject in non-secure contexts.
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Save your token"
      className="modal-overlay"
    >
      <div className="modal-card">
        <h2>Save your token</h2>
        <p className="subtitle">
          This is the only time the secret will be shown. If you lose it, revoke
          this token and create a new one.
        </p>

        {state.type === 'api_key' && state.apiKey && (
          <div className="field">
            <label>API key</label>
            <div className="secret-row">
              <code className="secret">{state.apiKey}</code>
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => copy(state.apiKey ?? '')}
              >
                Copy
              </button>
            </div>
          </div>
        )}

        {state.type === 'pat' && state.accessToken && (
          <>
            <div className="field">
              <label>Access token (PAT JWT)</label>
              <div className="secret-row">
                <code className="secret">{state.accessToken}</code>
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => copy(state.accessToken ?? '')}
                >
                  Copy
                </button>
              </div>
            </div>
            <div className="field">
              <label>Refresh token</label>
              <div className="secret-row">
                <code className="secret">{state.refreshToken}</code>
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => copy(state.refreshToken ?? '')}
                >
                  Copy
                </button>
              </div>
            </div>
          </>
        )}

        <label className="check-row">
          <input
            type="checkbox"
            checked={acked}
            onChange={(e) => setAcked(e.target.checked)}
          />
          <span>I have copied the token and stored it in a safe place.</span>
        </label>

        <div className="modal-actions">
          <button
            type="button"
            className="btn"
            disabled={!acked}
            onClick={onDismiss}
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
