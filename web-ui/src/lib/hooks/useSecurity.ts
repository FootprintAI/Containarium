'use client';

import useSWR from 'swr';
import { Server } from '@/src/types/server';
import { ClamavSummaryResponse } from '@/src/types/security';
import { getClient } from '@/src/lib/api/client';

/**
 * Hook for fetching ClamAV security summary
 */
export function useSecurity(server: Server | null) {
  const fetcher = async (): Promise<ClamavSummaryResponse> => {
    if (!server) throw new Error('No server');
    const client = getClient(server);
    return client.getClamavSummary();
  };

  const swrKey = server ? `security-summary-${server.id}` : null;

  const { data, error, isLoading, mutate } = useSWR<ClamavSummaryResponse>(
    swrKey,
    fetcher,
    {
      refreshInterval: 60000, // 60s refresh
      revalidateOnFocus: true,
      dedupingInterval: 10000,
    }
  );

  return {
    summary: data || null,
    isLoading,
    error,
    refresh: () => mutate(),
  };
}
