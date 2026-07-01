'use client';

import useSWR from 'swr';
import { Server } from '@/src/types/server';
import { ClamavSummaryResponse } from '@/src/types/security';
import { getClient } from '@/src/lib/api/client';
import { usePageVisibility } from './usePageVisibility';

export interface SecurityBadge {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export function useSecurity(server: Server | null) {
  const isVisible = usePageVisibility();
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
      refreshInterval: isVisible ? 60000 : 0,
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

export function useContainerSecurityBadges(server: Server | null, containerNames: string[]) {
  const isVisible = usePageVisibility();
  const sortedNames = [...containerNames].sort();
  const swrKey = server && sortedNames.length > 0
    ? `security-badges-${server.id}-${sortedNames.join(',')}`
    : null;

  const fetcher = async (): Promise<Record<string, SecurityBadge | null>> => {
    if (!server) throw new Error('No server');
    const client = getClient(server);
    const results = await Promise.all(
      sortedNames.map(async (name) => {
        try {
          const resp = await client.listPentestFindings({ containerName: name, status: 'open', limit: 200 });
          const badge: SecurityBadge = { critical: 0, high: 0, medium: 0, low: 0 };
          for (const f of resp.findings || []) {
            const sev = f.severity?.toLowerCase();
            if (sev === 'critical') badge.critical++;
            else if (sev === 'high') badge.high++;
            else if (sev === 'medium') badge.medium++;
            else if (sev === 'low') badge.low++;
          }
          return [name, badge] as [string, SecurityBadge];
        } catch {
          return [name, null] as [string, null];
        }
      })
    );
    return Object.fromEntries(results);
  };

  const { data, isLoading } = useSWR<Record<string, SecurityBadge | null>>(
    swrKey,
    fetcher,
    {
      refreshInterval: isVisible ? 300000 : 0,
      revalidateOnFocus: false,
      dedupingInterval: 60000,
    }
  );

  return {
    badgesMap: data || {},
    isLoading,
  };
}
