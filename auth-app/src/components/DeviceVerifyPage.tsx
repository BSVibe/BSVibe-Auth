'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';

interface SessionResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

type VerifyStatus = 'approved' | 'denied';

interface VerifyResponse {
  status: VerifyStatus;
}

interface DeviceLookupResponse {
  user_code: string;
  client_id: string | null;
  scope: string[];
  audience: string[];
  expires_at: string;
}

const USER_CODE_PATTERN = /^[A-Z0-9]{4}-[A-Z0-9]{4}$/;

function buildLoginRedirect(userCode: string): string {
  const dest = `/oauth/device/verify?user_code=${userCode}`;
  return `/login?redirect=${encodeURIComponent(dest)}`;
}

export function DeviceVerifyPage() {
  const searchParams = useSearchParams();
  const userCode = useMemo(
    () => (searchParams?.get('user_code') ?? '').toUpperCase(),
    [searchParams],
  );

  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [bootstrapError, setBootstrapError] = useState<string | null>(null);
  const [details, setDetails] = useState<DeviceLookupResponse | null>(null);
  const [detailsError, setDetailsError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [result, setResult] = useState<VerifyStatus | null>(null);

  useEffect(() => {
    if (!userCode || !USER_CODE_PATTERN.test(userCode)) return;
    let cancelled = false;
    async function bootstrap() {
      try {
        const resp = await fetch('/api/session', {
          method: 'GET',
          credentials: 'same-origin',
        });
        if (resp.status === 401) {
          window.location.href = buildLoginRedirect(userCode);
          return;
        }
        if (!resp.ok) {
          if (!cancelled) {
            setBootstrapError(`Session check failed (${resp.status})`);
          }
          return;
        }
        const body = (await resp.json()) as SessionResponse;
        if (!cancelled) setAccessToken(body.access_token);
      } catch (err) {
        if (!cancelled) {
          setBootstrapError(
            err instanceof Error ? err.message : 'Session check failed',
          );
        }
      }
    }
    bootstrap();
    return () => {
      cancelled = true;
    };
  }, [userCode]);

  // Fetch what the device is asking for so the user can decide informed.
  // Failure is non-fatal — we still let the user approve/deny — but we tell
  // them we couldn't load the details so they know to be cautious.
  useEffect(() => {
    if (!accessToken || !userCode) return;
    let cancelled = false;
    async function loadDetails() {
      try {
        const resp = await fetch(
          `/api/oauth/device/lookup?user_code=${encodeURIComponent(userCode)}`,
          {
            method: 'GET',
            headers: { Authorization: `Bearer ${accessToken}` },
            credentials: 'same-origin',
          },
        );
        if (cancelled) return;
        if (!resp.ok) {
          const errBody = (await resp.json().catch(() => ({}))) as {
            error?: string;
          };
          setDetailsError(
            errBody.error || `Could not load device details (${resp.status})`,
          );
          return;
        }
        const body = (await resp.json()) as DeviceLookupResponse;
        setDetails(body);
        setDetailsError(null);
      } catch (err) {
        if (!cancelled) {
          setDetailsError(
            err instanceof Error
              ? err.message
              : 'Could not load device details',
          );
        }
      }
    }
    loadDetails();
    return () => {
      cancelled = true;
    };
  }, [accessToken, userCode]);

  const submit = useCallback(
    async (action: 'approve' | 'deny') => {
      if (!accessToken || submitting) return;
      setSubmitting(true);
      setSubmitError(null);
      try {
        const resp = await fetch('/api/oauth/device/verify', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${accessToken}`,
          },
          credentials: 'same-origin',
          body: JSON.stringify({ user_code: userCode, action }),
        });
        if (!resp.ok) {
          const errBody = (await resp.json().catch(() => ({}))) as {
            error?: string;
          };
          setSubmitError(errBody.error || `Verify failed (${resp.status})`);
          return;
        }
        const body = (await resp.json()) as VerifyResponse;
        setResult(body.status);
      } catch (err) {
        setSubmitError(err instanceof Error ? err.message : 'Verify failed');
      } finally {
        setSubmitting(false);
      }
    },
    [accessToken, submitting, userCode],
  );

  if (!userCode) {
    return (
      <div className="tokens-dashboard">
        <h1>Authorize device</h1>
        <div className="error-box">
          Missing user_code. Open the link your device showed, or paste the
          code from the device into the URL.
        </div>
      </div>
    );
  }

  if (!USER_CODE_PATTERN.test(userCode)) {
    return (
      <div className="tokens-dashboard">
        <h1>Authorize device</h1>
        <div className="error-box">
          Invalid user_code format. Expected XXXX-XXXX.
        </div>
      </div>
    );
  }

  if (bootstrapError) {
    return (
      <div className="tokens-dashboard">
        <h1>Authorize device</h1>
        <div className="error-box">{bootstrapError}</div>
      </div>
    );
  }

  if (!accessToken) {
    return (
      <div className="tokens-dashboard">
        <p className="subtitle">Loading…</p>
      </div>
    );
  }

  return (
    <div className="tokens-dashboard">
      <header className="tokens-header">
        <h1>Authorize device</h1>
      </header>

      <p>A device is requesting access to your BSVibe account.</p>
      <p className="subtitle">
        Confirm that the code below matches the one shown on your device.
      </p>

      <div className="device-code-display">
        <code className="device-code">{userCode}</code>
      </div>

      {details && (
        <dl className="device-details">
          {details.client_id && (
            <>
              <dt>Client</dt>
              <dd><code>{details.client_id}</code></dd>
            </>
          )}
          <dt>Scopes</dt>
          <dd>
            {details.scope.length === 0 ? (
              <em>none</em>
            ) : (
              <ul className="device-scope-list">
                {details.scope.map((s) => (
                  <li key={s}><code>{s}</code></li>
                ))}
              </ul>
            )}
          </dd>
          <dt>Audience</dt>
          <dd>
            {details.audience.length === 0 ? (
              <em>none</em>
            ) : (
              details.audience.join(', ')
            )}
          </dd>
        </dl>
      )}
      {!details && detailsError && (
        <div className="error-box">{detailsError}</div>
      )}

      {submitError && <div className="error-box">{submitError}</div>}

      {result === null ? (
        <div className="modal-actions">
          <button
            type="button"
            className="btn btn-warn"
            disabled={submitting}
            onClick={() => submit('deny')}
          >
            {submitting ? 'Working…' : 'Deny'}
          </button>
          <button
            type="button"
            className="btn"
            disabled={submitting}
            onClick={() => submit('approve')}
          >
            {submitting ? 'Working…' : 'Approve'}
          </button>
        </div>
      ) : (
        <div className="device-result">
          {result === 'approved' ? (
            <p className="success-box">
              Approved. You can close this tab and return to your device.
            </p>
          ) : (
            <p className="error-box">
              Denied. The device will not receive access.
            </p>
          )}
          <Link href="/dashboard/tokens">← Back to tokens</Link>
        </div>
      )}
    </div>
  );
}
