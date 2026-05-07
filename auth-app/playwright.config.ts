import { defineConfig, devices } from '@playwright/test';

const MOCK_SUPABASE_URL = 'http://127.0.0.1:5180';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: 'list',
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  use: {
    baseURL: 'http://localhost:5179',
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'next dev -p 5179',
    url: 'http://localhost:5179',
    reuseExistingServer: !process.env.CI,
    env: {
      // Browser-side: keep the public stub so existing /login redirect
      // assertions in auth.spec.ts continue to point at test.supabase.co.
      NEXT_PUBLIC_SUPABASE_URL: 'https://test.supabase.co',
      NEXT_PUBLIC_SUPABASE_ANON_KEY: 'test-anon-key',
      NEXT_PUBLIC_ALLOWED_REDIRECT_ORIGINS: 'http://localhost:5179,http://example.com',
      // Server-side: point at the in-memory mock started by global-setup.ts.
      SUPABASE_URL: MOCK_SUPABASE_URL,
      SUPABASE_ANON_KEY: 'test-anon-key',
      SUPABASE_SERVICE_ROLE_KEY: 'test-service-role-key',
      SERVICE_TOKEN_SIGNING_SECRET:
        'test-service-token-signing-secret-256-bits-minimum-length-pad-pad-pad',
      SERVICE_TOKEN_ISSUER: 'https://auth.bsvibe.dev',
      AUTH_PUBLIC_BASE_URL: 'http://localhost:5179',
      ALLOWED_REDIRECT_ORIGINS: 'http://localhost:5179,http://example.com',
    },
  },
});
