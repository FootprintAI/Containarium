'use client';

import useSWR from 'swr';
import { Server } from '@/src/types/server';
import { AuditLogsResponse, AuditLogsParams } from '@/src/types/audit';
import { getClient } from '@/src/lib/api/client';

/**
 * Hook for fetching audit logs with filtering and pagination
 */
export function useAudit(server: Server | null, params?: AuditLogsParams) {
  const fetcher = async (): Promise<AuditLogsResponse> => {
    if (!server) throw new Error('No server');
    const client = getClient(server);
    return client.getAuditLogs(params);
  };

  // Include params in the SWR key so changes trigger refetch
  const swrKey = server
    ? `audit-logs-${server.id}-${JSON.stringify(params || {})}`
    : null;

  const { data, error, isLoading, mutate } = useSWR<AuditLogsResponse>(
    swrKey,
    fetcher,
    {
      refreshInterval: 30000, // 30s refresh
      revalidateOnFocus: true,
      dedupingInterval: 5000,
    }
  );

  return {
    logs: data?.logs || [],
    totalCount: data?.totalCount || 0,
    isLoading,
    error,
    refresh: () => mutate(),
  };
}
