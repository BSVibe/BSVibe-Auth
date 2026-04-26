/**
 * redirect_uri allow-list validation — used by client components.
 *
 * Phase Z: env var migrated from `import.meta.env.ALLOWED_REDIRECT_ORIGINS`
 * to `process.env.NEXT_PUBLIC_ALLOWED_REDIRECT_ORIGINS`. Vitest also writes to
 * `process.env.ALLOWED_REDIRECT_ORIGINS`, so we accept either name.
 */
const allowedOrigins: string[] = (
  process.env.NEXT_PUBLIC_ALLOWED_REDIRECT_ORIGINS ??
  process.env.ALLOWED_REDIRECT_ORIGINS ??
  ''
)
  .split(',')
  .map((o: string) => o.trim())
  .filter(Boolean);

export function validateRedirectUri(redirectUri: string | null): {
  valid: boolean;
  error?: string;
} {
  if (!redirectUri) {
    return { valid: false, error: 'Missing redirect_uri parameter' };
  }

  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    return { valid: false, error: 'Invalid redirect_uri format' };
  }

  const origin = parsed.origin;

  const isAllowed = allowedOrigins.some((entry) => {
    if (entry.endsWith(':*')) {
      const prefix = entry.slice(0, -2);
      return origin === prefix || origin.startsWith(prefix + ':');
    }
    return origin === entry;
  });

  if (!isAllowed) {
    return {
      valid: false,
      error: `Redirect origin "${origin}" is not allowed`,
    };
  }

  return { valid: true };
}

export function buildCallbackUrl(
  redirectUri: string,
  params: {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    state?: string;
  }
): string {
  const qs = new URLSearchParams();
  qs.set('access_token', params.access_token);
  qs.set('refresh_token', params.refresh_token);
  qs.set('expires_in', String(params.expires_in));
  if (params.state) {
    qs.set('state', params.state);
  }
  return `${redirectUri}#${qs.toString()}`;
}
