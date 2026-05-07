import Link from 'next/link';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="dashboard-shell">
      <nav className="dashboard-nav">
        <Link href="/" className="logo">
          BSVibe
        </Link>
        <Link href="/dashboard/tokens">Tokens</Link>
      </nav>
      <main className="dashboard-main">{children}</main>
    </div>
  );
}
