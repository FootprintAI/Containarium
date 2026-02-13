'use client';

import { useCallback } from 'react';
import useSWR from 'swr';
import { App } from '@/src/types/app';
import { Server } from '@/src/types/server';
import { getClient } from '@/src/lib/api/client';
import { useEventStream } from '@/src/lib/events/useEventStream';
import { ServerEvent, isAppEvent } from '@/src/types/events';

/**
 * Hook for managing apps for a specific server
 */
export function useApps(server: Server | null, username?: string) {
  // Create a stable fetcher for this server
  const fetcher = async (): Promise<App[]> => {
    if (!server) return [];
    const client = getClient(server);
    return client.listApps(username);
  };

  // SWR key is based on server endpoint to ensure proper caching
  const swrKey = server ? `apps-${server.id}-${username || 'all'}` : null;

  const { data, error, isLoading, mutate } = useSWR<App[]>(
    swrKey,
    fetcher,
    {
      // No polling - rely on SSE for real-time updates
      refreshInterval: 0,
      revalidateOnFocus: true,
      dedupingInterval: 5000,
    }
  );

  // Handle app events from SSE
  const handleEvent = useCallback(
    (event: ServerEvent) => {
      if (!isAppEvent(event)) return;

      // Revalidate app list on any app event
      mutate();
    },
    [mutate]
  );

  // Subscribe to app events via SSE
  const { status: eventStatus, reconnect } = useEventStream(server, {
    resourceTypes: ['RESOURCE_TYPE_APP'],
    onEvent: handleEvent,
  });

  /**
   * Stop an app
   */
  const stopApp = async (appUsername: string, appName: string) => {
    if (!server) throw new Error('No server selected');

    const client = getClient(server);
    const app = await client.stopApp(appUsername, appName);

    // Revalidate app list
    await mutate();

    return app;
  };

  /**
   * Start an app
   */
  const startApp = async (appUsername: string, appName: string) => {
    if (!server) throw new Error('No server selected');

    const client = getClient(server);
    const app = await client.startApp(appUsername, appName);

    // Revalidate app list
    await mutate();

    return app;
  };

  /**
   * Restart an app
   */
  const restartApp = async (appUsername: string, appName: string) => {
    if (!server) throw new Error('No server selected');

    const client = getClient(server);
    const app = await client.restartApp(appUsername, appName);

    // Revalidate app list
    await mutate();

    return app;
  };

  /**
   * Delete an app
   */
  const deleteApp = async (appUsername: string, appName: string, removeData: boolean = false) => {
    if (!server) throw new Error('No server selected');

    const client = getClient(server);
    await client.deleteApp(appUsername, appName, removeData);

    // Revalidate app list
    await mutate();
  };

  /**
   * Get app logs
   */
  const getAppLogs = async (appUsername: string, appName: string, tailLines: number = 100) => {
    if (!server) throw new Error('No server selected');

    const client = getClient(server);
    return client.getAppLogs(appUsername, appName, tailLines);
  };

  /**
   * Refresh app list
   */
  const refresh = () => mutate();

  return {
    apps: data || [],
    isLoading,
    error,
    stopApp,
    startApp,
    restartApp,
    deleteApp,
    getAppLogs,
    refresh,
    // Event stream status
    eventStatus,
    reconnectEvents: reconnect,
  };
}
