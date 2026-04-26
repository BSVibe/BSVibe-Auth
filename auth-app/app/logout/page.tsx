import { Suspense } from 'react';
import { LogoutPage } from '@/src/components/LogoutPage';

export default function Page() {
  return (
    <Suspense fallback={null}>
      <LogoutPage />
    </Suspense>
  );
}
