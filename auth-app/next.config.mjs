/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Security headers for /api/* are handled per-route via NextResponse.
  async rewrites() {
    return [
      {
        source: '/.well-known/jwks.json',
        destination:
          'https://hobuqhkrqqhuvpxofdcc.supabase.co/auth/v1/.well-known/jwks.json',
      },
    ];
  },
};

export default nextConfig;
