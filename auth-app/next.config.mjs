/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  allowedDevOrigins: ['bsserver'],
  devIndicators: false,
  // Security headers for /api/* are handled per-route via NextResponse.
  async rewrites() {
    return [
      {
        source: '/.well-known/jwks.json',
        destination:
          'https://hobuqhkrqqhuvpxofdcc.supabase.co/auth/v1/.well-known/jwks.json',
      },
      // OAuth 2.0 Device Authorization Grant (RFC 8628) — expose the
      // device-flow endpoints at the conventional non-/api paths so OAuth
      // clients that follow the RFC defaults (Auth0, Google, our own
      // bsvibe-cli-base DeviceFlowClient) work out of the box. The route
      // handlers live under /api/oauth/device/* by Next.js convention; the
      // /api prefix is an implementation detail callers should not see.
      { source: '/oauth/device/code', destination: '/api/oauth/device/code' },
      { source: '/oauth/device/token', destination: '/api/oauth/device/token' },
      // Round 5 — OAuth 2.0 authorization_code grant + supporting metadata
      // (RFC 6749 §4.1 / RFC 7591 DCR / RFC 8414 server metadata / RFC 7009
      // revocation / RFC 7662 introspection alias). Same /api hiding
      // pattern as the device-flow endpoints above.
      { source: '/oauth/authorize', destination: '/api/oauth/authorize' },
      { source: '/oauth/token', destination: '/api/oauth/token' },
      { source: '/oauth/register', destination: '/api/oauth/register' },
      { source: '/oauth/revoke', destination: '/api/oauth/revoke' },
      { source: '/oauth/introspect', destination: '/api/oauth/introspect' },
      {
        source: '/.well-known/oauth-authorization-server',
        destination: '/api/.well-known/oauth-authorization-server',
      },
    ];
  },
};

export default nextConfig;
