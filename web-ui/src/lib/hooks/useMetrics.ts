'use client';

import { useRef, useMemo } from 'react';
import useSWR from 'swr';
import { ContainerMetrics, ContainerMetricsWithRate } from '@/src/types/container';
import { Server } from '@/src/types/server';
import { getClient } from '@/src/lib/api/client';
import { usePageVisibility } from './usePageVisibility';

interface MetricsSnapshot {
  metrics: Record<string, ContainerMetrics>;
  timestamp: number;
}

/**
 * Hook for fetching container metrics with polling and CPU rate calculation
 */
export function useMetrics(server: Server | null, enabled: boolean = true) {
  const isVisible = usePageVisibility();
  // Store previous metrics for CPU rate calculation
  const prevSnapshot = useRef<MetricsSnapshot | null>(null);

  const fetcher = async (): Promise<ContainerMetrics[]> => {
    if (!server) return [];
    const client = getClient(server);
    return client.getMetrics();
  };

  const swrKey = server && enabled ? 'metrics-' + server.id : null;

  const { data, error, isLoading, mutate } = useSWR<ContainerMetrics[]>(
    swrKey,
    fetcher,
    {
      refreshInterval: (() => { const interval = isVisible ? 5000 : 0; console.log('[useMetrics] refreshInterval:', interval, 'isVisible:', isVisible); return interval; })(),
      revalidateOnFocus: true,
      dedupingInterval: 2000,
    }
  );

  // Calculate CPU rate by comparing with previous snapshot
  const metricsWithRate = useMemo((): ContainerMetricsWithRate[] => {
    if (!data || data.length === 0) return [];

    const now = Date.now();
    const currentMap: Record<string, ContainerMetrics> = {};
    for (const m of data) {
      currentMap[m.name] = m;
    }

    const result: ContainerMetricsWithRate[] = [];

    for (const m of data) {
      let cpuUsagePercent = 0;

      // Calculate CPU rate if we have previous data
      if (prevSnapshot.current) {
        const prev = prevSnapshot.current.metrics[m.name];
        const elapsedMs = now - prevSnapshot.current.timestamp;

        if (prev && elapsedMs > 0) {
          const cpuDelta = m.cpuUsageSeconds - prev.cpuUsageSeconds;
          const elapsedSeconds = elapsedMs / 1000;

          // CPU percentage: (cpu seconds used / elapsed seconds) * 100
          // Can exceed 100% with multiple cores
          if (cpuDelta >= 0 && elapsedSeconds > 0) {
            cpuUsagePercent = (cpuDelta / elapsedSeconds) * 100;
          }
        }
      }

      result.push({
        ...m,
        cpuUsagePercent,
      });
    }

    // Update previous snapshot for next calculation
    prevSnapshot.current = {
      metrics: currentMap,
      timestamp: now,
    };

    return result;
  }, [data]);

  /**
   * Get metrics for a specific container by name
   */
  const getContainerMetrics = (containerName: string): ContainerMetricsWithRate | undefined => {
    return metricsWithRate.find(m => m.name === containerName);
  };

  /**
   * Manually refresh metrics
   */
  const refresh = () => mutate();

  return {
    metrics: metricsWithRate,
    isLoading,
    error,
    getContainerMetrics,
    refresh,
  };
}
