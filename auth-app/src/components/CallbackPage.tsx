'use client';

import { useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { validateRedirectUri, buildCallbackUrl } from '../lib/redirect';

export function CallbackPage() {
  const searchParams = useSearchParams();
  const redirectUri = searchParams?.get('redirect_uri') ?? null;
  const state = searchParams?.get('state') ?? null;
  const [error, setError] = useState('');

  useEffect(() => {
    async function handleCallback() {
      const hash = window.location.hash.substring(1);
      const params = new URLSearchParams(hash);

      // Check for OAuth error
      const oauthError = params.get('error_description') || params.get('error');
      if (oauthError) {
        setError(oauthError);
        return;
      }

      const accessToken = params.get('access_token');
      const refreshToken = params.get('refresh_token');
      const expiresIn = params.get('expires_in');

      if (!accessToken || !refreshToken || !expiresIn) {
        setError('Missing authentication tokens');
        return;
      }

      // Set shared domain cookie (Domain=.bsvibe.dev)
      try {
        await fetch('/api/session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),
          credentials: 'same-origin',
        });
      } catch {
        // Best effort — cookie may fail in non-bsvibe.dev environments
      }

      if (!redirectUri) {
        // No redirect_uri: shared cookie is set, go to main site
        navigateTo('https://bsvibe.dev/account');
        return;
      }

      const validation = validateRedirectUri(redirectUri);
      if (!validation.valid) {
        setError(validation.error || 'Invalid redirect URI');
        return;
      }

      // Redirect to product — token in hash for backward compat
      // Products migrated to server-side auth can ignore the hash
      // and just read the shared bsvibe_session cookie
      const callbackUrl = buildCallbackUrl(redirectUri, {
        access_token: accessToken,
        refresh_token: refreshToken,
        expires_in: Number(expiresIn),
        state: state || undefined,
      });
      navigateTo(callbackUrl);
    }

    function navigateTo(url: string) {
      // E2E test hook: capture target URL instead of navigating
      // (cross-origin window.location.href can't be intercepted by Playwright)
      const w = window as Window & { __E2E_REDIRECT_TARGET__?: string };
      if (w.__E2E_REDIRECT_TARGET__ !== undefined) {
        w.__E2E_REDIRECT_TARGET__ = url;
        return;
      }
      window.location.href = url;
    }

    handleCallback();
  }, [redirectUri, state]);

  const queryString = searchParams?.toString() ?? '';
  const loginLink = `/login${queryString ? `?${queryString}` : ''}`;

  return (
    <div className="container">
      <div className="card">
        <h1 className="logo">BSVibe</h1>
        {error ? (
          <>
            <div className="error-box">{error}</div>
            <p className="link-text">
              <Link href={loginLink}>Back to sign in</Link>
            </p>
          </>
        ) : (
          <p className="subtitle">Completing sign-in…</p>
        )}
      </div>
    </div>
  );
}
