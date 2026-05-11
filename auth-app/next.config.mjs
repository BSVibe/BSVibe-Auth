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
    ];
  },
};

export default nextConfig;
