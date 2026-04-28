import '@testing-library/jest-dom/vitest';

/**
 * Phase Z: Next.js 15 client components import `next/navigation` and
 * `next/link`. Under Vitest+jsdom we mock both globally — the router itself
 * isn't exercised, only the searchParams and Link rendering.
 *
 * Per-test cases override `useSearchParams()` via `__setMockSearchParams()`.
 */
import { vi } from 'vitest';
import React from 'react';

const searchParamsState: { value: URLSearchParams } = {
  value: new URLSearchParams(),
};

declare global {
  var __setMockSearchParams: (init: string | URLSearchParams) => void;
}

globalThis.__setMockSearchParams = (init: string | URLSearchParams) => {
  searchParamsState.value =
    typeof init === 'string' ? new URLSearchParams(init) : init;
};

vi.mock('next/navigation', () => ({
  useSearchParams: () => searchParamsState.value,
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
    refresh: vi.fn(),
    prefetch: vi.fn(),
  }),
  usePathname: () => '/',
  redirect: vi.fn(),
}));

vi.mock('next/link', () => ({
  default: ({
    href,
    children,
    ...rest
  }: {
    href: string;
    children: React.ReactNode;
  }) =>
    React.createElement(
      'a',
      { href, ...rest },
      children,
    ),
}));
