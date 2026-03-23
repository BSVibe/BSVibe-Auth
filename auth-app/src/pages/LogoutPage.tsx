import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { signOut } from '../lib/supabase';
import { validateRedirectUri } from '../lib/redirect';

export function LogoutPage() {
  const [searchParams] = useSearchParams();
  const redirectUri = searchParams.get('redirect_uri');
  const [status, setStatus] = useState('Signing out\u2026');

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

      if (redirectUri) {
        const validation = validateRedirectUri(redirectUri);
        if (validation.valid) {
          window.location.href = redirectUri;
          return;
        }
      }

      setStatus('You have been signed out.');
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
