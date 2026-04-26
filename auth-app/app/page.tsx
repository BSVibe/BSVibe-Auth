import { redirect } from 'next/navigation';

export default function RootPage() {
  // Default landing → /login (preserves Vite SPA behavior of redirecting unknown routes)
  redirect('/login');
}
