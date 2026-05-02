import { Suspense } from 'react';
import { SignupPage } from '@/src/components/SignupPage';

export default function Page() {
  return (
    <Suspense fallback={null}>
      <SignupPage />
    </Suspense>
  );
}
