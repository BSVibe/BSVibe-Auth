import { useState, useMemo } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import { signUp } from '../lib/supabase';
import { validateRedirectUri, buildCallbackUrl } from '../lib/redirect';

export function SignupPage() {
  const [searchParams] = useSearchParams();
  const redirectUri = searchParams.get('redirect_uri');
  const state = searchParams.get('state');

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const validation = useMemo(() => validateRedirectUri(redirectUri), [redirectUri]);

  const loginLink = `/login${searchParams.toString() ? `?${searchParams.toString()}` : ''}`;

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!validation.valid || !redirectUri) return;

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setError('');
    setLoading(true);

    try {
      const result = await signUp(email, password);

      // Set session cookie for SSO
      try {
        await fetch('/api/session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: result.refresh_token }),
          credentials: 'same-origin',
        });
      } catch {
        // Best effort — SSO cookie is not critical for signup flow
      }

      const callbackUrl = buildCallbackUrl(redirectUri, {
        access_token: result.access_token,
        refresh_token: result.refresh_token,
        expires_in: result.expires_in,
        state: state || undefined,
      });
      window.location.href = callbackUrl;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Signup failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="container">
      <div className="card">
        <h1 className="logo">BSVibe</h1>
        <p className="subtitle">Create your account</p>

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
                placeholder="At least 8 characters"
                required
                minLength={8}
                disabled={loading}
              />
            </div>
            <div className="field">
              <label htmlFor="confirmPassword">Confirm password</label>
              <input
                id="confirmPassword"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm your password"
                required
                minLength={8}
                disabled={loading}
              />
            </div>
            <button type="submit" className="btn" disabled={loading}>
              {loading ? 'Creating account\u2026' : 'Create account'}
            </button>
            <p className="link-text">
              Already have an account? <Link to={loginLink}>Sign in</Link>
            </p>
          </form>
        )}
      </div>
    </div>
  );
}
