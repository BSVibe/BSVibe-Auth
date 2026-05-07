import type { MockSupabase } from "./mock-supabase/server";

declare global {
  var __mockSupabase: MockSupabase | undefined;
}

export default async function globalTeardown(): Promise<void> {
  const mock = globalThis.__mockSupabase;
  if (!mock) return;
  await mock.close();
  globalThis.__mockSupabase = undefined;
}
