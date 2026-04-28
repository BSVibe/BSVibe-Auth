import { Suspense } from 'react';
import { LoginPage } from '@/src/components/LoginPage';

// useSearchParams() requires a Suspense boundary in the Next.js 15 App Router.
export default function Page() {
  return (
    <Suspense fallback={null}>
      <LoginPage />
    </Suspense>
  );
}
