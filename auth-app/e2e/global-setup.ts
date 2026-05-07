/**
 * Playwright globalSetup — start the in-memory mock Supabase server on
 * a fixed port (5180) so the Next dev server (started by webServer config)
 * can reach it via the SUPABASE_URL env var declared in playwright.config.ts.
 *
 * Pairs with global-teardown.ts which closes the server.
 */

import { startMockSupabase, type MockSupabase } from "./mock-supabase/server";

declare global {
  var __mockSupabase: MockSupabase | undefined;
}

export const MOCK_SUPABASE_PORT = 5180;

export default async function globalSetup(): Promise<void> {
  if (globalThis.__mockSupabase) return;
  const mock = await startMockSupabase(MOCK_SUPABASE_PORT);
  globalThis.__mockSupabase = mock;
  console.log(`[mock-supabase] listening on ${mock.url}`);
}
