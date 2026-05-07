import { Suspense } from 'react';
import { DeviceVerifyPage } from '@/src/components/DeviceVerifyPage';

export default function Page() {
  return (
    <Suspense fallback={null}>
      <DeviceVerifyPage />
    </Suspense>
  );
}
