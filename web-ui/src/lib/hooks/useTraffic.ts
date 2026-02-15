'use client';

import { useCallback, useState } from 'react';
import useSWR from 'swr';
import { Server } from '@/src/types/server';
import { Connection, ConnectionSummary, HistoricalConnection, TrafficAggregate } from '@/src/types/traffic';
import { getClient } from '@/src/lib/api/client';
import { useEventStream } from '@/src/lib/events/useEventStream';
import { ServerEvent } from '@/src/types/events';

/**
 * Hook for managing traffic monitoring for a specific container
 */
export function useTraffic(server: Server | null, containerName: string | null) {
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Fetcher for active connections
  const connectionsFetcher = async (): Promise<Connection[]> => {
    if (!server || !containerName) return [];
    const client = getClient(server);
    const response = await client.getConnections(containerName, { limit: 200 });
    return response.connections;
  };

  // SWR key for connections
  const connectionsKey = server && containerName ? `traffic-connections-${server.id}-${containerName}` : null;

  const {
    data: connections,
    error: connectionsError,
    isLoading: connectionsLoading,
    mutate: mutateConnections,
  } = useSWR<Connection[]>(connectionsKey, connectionsFetcher, {
    refreshInterval: autoRefresh ? 5000 : 0, // Poll every 5 seconds if auto-refresh enabled
    revalidateOnFocus: true,
    dedupingInterval: 2000,
  });

  // Fetcher for connection summary
  const summaryFetcher = async (): Promise<ConnectionSummary | null> => {
    if (!server || !containerName) return null;
    const client = getClient(server);
    return client.getConnectionSummary(containerName);
  };

  // SWR key for summary
  const summaryKey = server && containerName ? `traffic-summary-${server.id}-${containerName}` : null;

  const {
    data: summary,
    error: summaryError,
    isLoading: summaryLoading,
    mutate: mutateSummary,
  } = useSWR<ConnectionSummary | null>(summaryKey, summaryFetcher, {
    refreshInterval: autoRefresh ? 5000 : 0,
    revalidateOnFocus: true,
    dedupingInterval: 2000,
  });

  // Handle traffic events from SSE
  const handleEvent = useCallback(
    (event: ServerEvent) => {
      // Check if this is a traffic event for our container
      if (event.type === 'EVENT_TYPE_TRAFFIC_UPDATE' && event.resourceId === containerName) {
        mutateConnections();
        mutateSummary();
      }
    },
    [containerName, mutateConnections, mutateSummary]
  );

  // Subscribe to traffic events via SSE
  const { status: eventStatus } = useEventStream(server, {
    resourceTypes: ['RESOURCE_TYPE_TRAFFIC'],
    onEvent: handleEvent,
  });

  /**
   * Get traffic history for a time range
   */
  const getTrafficHistory = async (options: {
    startTime: Date;
    endTime: Date;
    destIp?: string;
    destPort?: number;
    offset?: number;
    limit?: number;
  }): Promise<{ connections: HistoricalConnection[]; totalCount: number }> => {
    if (!server || !containerName) return { connections: [], totalCount: 0 };

    const client = getClient(server);
    return client.getTrafficHistory(containerName, {
      startTime: options.startTime.toISOString(),
      endTime: options.endTime.toISOString(),
      destIp: options.destIp,
      destPort: options.destPort,
      offset: options.offset,
      limit: options.limit,
    });
  };

  /**
   * Get traffic aggregates for a time range
   */
  const getTrafficAggregates = async (options: {
    startTime: Date;
    endTime: Date;
    interval?: string;
    groupByDestIp?: boolean;
    groupByDestPort?: boolean;
  }): Promise<TrafficAggregate[]> => {
    if (!server || !containerName) return [];

    const client = getClient(server);
    return client.getTrafficAggregates(containerName, {
      startTime: options.startTime.toISOString(),
      endTime: options.endTime.toISOString(),
      interval: options.interval,
      groupByDestIp: options.groupByDestIp,
      groupByDestPort: options.groupByDestPort,
    });
  };

  /**
   * Refresh connections and summary
   */
  const refresh = () => {
    mutateConnections();
    mutateSummary();
  };

  /**
   * Toggle auto-refresh
   */
  const toggleAutoRefresh = () => {
    setAutoRefresh((prev) => !prev);
  };

  return {
    // Current state
    connections: connections || [],
    summary: summary || null,
    isLoading: connectionsLoading || summaryLoading,
    error: connectionsError || summaryError,
    autoRefresh,

    // Actions
    refresh,
    toggleAutoRefresh,
    getTrafficHistory,
    getTrafficAggregates,

    // Event stream status
    eventStatus,
  };
}

/**
 * Hook for getting traffic history with SWR caching
 */
export function useTrafficHistory(
  server: Server | null,
  containerName: string | null,
  startTime: Date,
  endTime: Date
) {
  const historyFetcher = async (): Promise<{
    connections: HistoricalConnection[];
    totalCount: number;
  }> => {
    if (!server || !containerName) return { connections: [], totalCount: 0 };
    const client = getClient(server);
    return client.getTrafficHistory(containerName, {
      startTime: startTime.toISOString(),
      endTime: endTime.toISOString(),
      limit: 100,
    });
  };

  const historyKey =
    server && containerName
      ? `traffic-history-${server.id}-${containerName}-${startTime.getTime()}-${endTime.getTime()}`
      : null;

  const { data, error, isLoading, mutate } = useSWR(historyKey, historyFetcher, {
    refreshInterval: 0,
    revalidateOnFocus: false,
    dedupingInterval: 10000,
  });

  return {
    connections: data?.connections || [],
    totalCount: data?.totalCount || 0,
    isLoading,
    error,
    refresh: () => mutate(),
  };
}
