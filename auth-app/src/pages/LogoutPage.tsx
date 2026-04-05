import { useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { signOut } from '../lib/supabase';
import { validateRedirectUri } from '../lib/redirect';

export function LogoutPage() {
  const [searchParams] = useSearchParams();
  const redirectUri = searchParams.get('redirect_uri');
  const status = 'Signing out\u2026';

  useEffect(() => {
    async function doLogout() {
      // Try to sign out from Supabase if there's a token in the fragment
      const hash = window.location.hash.substring(1);
      const params = new URLSearchParams(hash);
      const token = params.get('access_token');

      if (token) {
        try {
          await signOut(token);
        } catch {
          // Best effort — continue with redirect even if signout fails
        }
      }

      // Clear SSO session cookie
      try {
        await fetch('/api/session', {
          method: 'DELETE',
          credentials: 'same-origin',
        });
      } catch {
        // Best effort — continue even if cookie clearing fails
      }

      if (redirectUri) {
        const validation = validateRedirectUri(redirectUri);
        if (validation.valid) {
          window.location.href = redirectUri;
          return;
        }
      }

      window.location.href = '/login';
    }

    doLogout();
  }, [redirectUri]);

  return (
    <div className="container">
      <div className="card">
        <h1 className="logo">BSVibe</h1>
        <p className="subtitle">{status}</p>
      </div>
    </div>
  );
}
