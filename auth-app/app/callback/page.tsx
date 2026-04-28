import { Suspense } from 'react';
import { CallbackPage } from '@/src/components/CallbackPage';

export default function Page() {
  return (
    <Suspense fallback={null}>
      <CallbackPage />
    </Suspense>
  );
}
