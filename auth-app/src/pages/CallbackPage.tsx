import { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { validateRedirectUri, buildCallbackUrl } from '../lib/redirect';

export function CallbackPage() {
  const [searchParams] = useSearchParams();
  const redirectUri = searchParams.get('redirect_uri');
  const state = searchParams.get('state');
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

      if (!redirectUri) {
        setError('Missing redirect_uri parameter');
        return;
      }

      const validation = validateRedirectUri(redirectUri);
      if (!validation.valid) {
        setError(validation.error || 'Invalid redirect URI');
        return;
      }

      // Set SSO session cookie (best effort)
      try {
        await fetch('/api/session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),
          credentials: 'same-origin',
        });
      } catch {
        // Best effort
      }

      const callbackUrl = buildCallbackUrl(redirectUri, {
        access_token: accessToken,
        refresh_token: refreshToken,
        expires_in: Number(expiresIn),
        state: state || undefined,
      });
      window.location.href = callbackUrl;
    }

    handleCallback();
  }, [redirectUri, state]);

  const loginLink = `/login${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;

  return (
    <div className="container">
      <div className="card">
        <h1 className="logo">BSVibe</h1>
        {error ? (
          <>
            <div className="error-box">{error}</div>
            <p className="link-text">
              <Link to={loginLink}>Back to sign in</Link>
            </p>
          </>
        ) : (
          <p className="subtitle">Completing sign-in…</p>
        )}
      </div>
    </div>
  );
}
