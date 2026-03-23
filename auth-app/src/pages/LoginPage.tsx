import { useState, useMemo, FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { signInWithPassword } from '../lib/supabase';
import { validateRedirectUri, buildCallbackUrl } from '../lib/redirect';

export function LoginPage() {
  const [searchParams] = useSearchParams();
  const redirectUri = searchParams.get('redirect_uri');
  const state = searchParams.get('state');

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const validation = useMemo(() => validateRedirectUri(redirectUri), [redirectUri]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!validation.valid || !redirectUri) return;

    setError('');
    setLoading(true);

    try {
      const result = await signInWithPassword(email, password);
      const callbackUrl = buildCallbackUrl(redirectUri, {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
        expires_in: result.expires_in,
        state: state || undefined,
      });
      window.location.href = callbackUrl;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="container">
      <div className="card">
        <h1 className="logo">BSVibe</h1>
        <p className="subtitle">Sign in to continue</p>

        {!validation.valid ? (
          <div className="error-box">{validation.error}</div>
        ) : (
          <form onSubmit={handleSubmit}>
            {error && <div className="error-box">{error}</div>}
            <div className="field">
              <label htmlFor="email">Email</label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                required
                autoFocus
                disabled={loading}
              />
            </div>
            <div className="field">
              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                required
                disabled={loading}
              />
            </div>
            <button type="submit" className="btn" disabled={loading}>
              {loading ? 'Signing in\u2026' : 'Sign in'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
