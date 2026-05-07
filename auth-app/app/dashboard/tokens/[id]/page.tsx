import { TokenDetailPage } from '@/src/components/TokenDetailPage';

export default async function Page({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <TokenDetailPage tokenId={id} />;
}
