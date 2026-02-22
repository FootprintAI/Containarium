'use client';

import { useCallback } from 'react';
import useSWR from 'swr';
import { Container, CreateContainerRequest, SystemInfo } from '@/src/types/container';
import { Server } from '@/src/types/server';
import { getClient } from '@/src/lib/api/client';
import { useEventStream } from '@/src/lib/events/useEventStream';
import { ServerEvent, isContainerEvent, ConnectionStatus } from '@/src/types/events';

export interface CreateContainerProgress {
  state: string;
  message: string;
}

/**
 * Hook for managing containers for a specific server
 */
export function useContainers(server: Server | null) {
  // Create a stable fetcher for this server
  const fetcher = async (): Promise<Container[]> => {
    if (!server) return [];
    const client = getClient(server);
    return client.listContainers();
  };

  // SWR key is based on server endpoint to ensure proper caching
  const swrKey = server ? 'containers-' + server.id : null;

  const { data, error, isLoading, mutate } = useSWR<Container[]>(
    swrKey,
    fetcher,
    {
      // No polling - rely on SSE for real-time updates
      refreshInterval: 0,
      revalidateOnFocus: true,
      dedupingInterval: 5000,
    }
  );

  // Handle container events from SSE
  const handleEvent = useCallback(
    (event: ServerEvent) => {
      if (!isContainerEvent(event)) return;

      // Revalidate container list on any container event
      mutate();
    },
    [mutate]
  );

  // Subscribe to container events via SSE
  const { status: eventStatus, reconnect } = useEventStream(server, {
    resourceTypes: ['RESOURCE_TYPE_CONTAINER'],
    onEvent: handleEvent,
  });

  // Fetch system info (including network CIDR)
  const systemInfoFetcher = async (): Promise<SystemInfo | null> => {
    if (!server) return null;
    const client = getClient(server);
    try {
      return await client.getSystemInfo();
    } catch {
      return null;
    }
  };

  const systemInfoKey = server ? 'systeminfo-' + server.id : null;
  const { data: systemInfo } = useSWR<SystemInfo | null>(
    systemInfoKey,
    systemInfoFetcher,
    {
      refreshInterval: 60000, // Refresh every minute
      revalidateOnFocus: false,
      dedupingInterval: 30000,
    }
  );

  /**
   * Create a new container with async API and polling for completion
   */
  const createContainer = async (
    request: CreateContainerRequest,
    onProgress?: (progress: CreateContainerProgress) => void
  ) => {
    if (!server) throw new Error('No server selected');

    const client = getClient(server);

    // Notify starting
    if (onProgress) {
      onProgress({ state: 'Creating', message: 'Initiating container creation...' });
    }

    // Initiate async container creation (returns immediately)
    await client.createContainer(request, true);

    // Poll for completion
    if (onProgress) {
      onProgress({ state: 'Creating', message: 'Container is being provisioned...' });
    }

    const container = await client.waitForContainer(
      request.username,
      (state, message) => {
        if (onProgress) {
          onProgress({ state, message });
        }
      }
    );

    // Revalidate container list
    await mutate();

    return container;
  };

  /**
   * Delete a container
   */
  const deleteContainer = async (username: string, force: boolean = false) => {
    if (!server) throw new Error('No server selected');

    const client = getClient(server);
    await client.deleteContainer(username, force);

    // Revalidate container list
    await mutate();
  };

  /**
   * Start a container
   */
  const startContainer = async (username: string) => {
    if (!server) throw new Error('No server selected');

    const client = getClient(server);
    const container = await client.startContainer(username);

    // Revalidate container list
    await mutate();

    return container;
  };

  /**
   * Stop a container
   */
  const stopContainer = async (username: string, force: boolean = false) => {
    if (!server) throw new Error('No server selected');

    const client = getClient(server);
    const container = await client.stopContainer(username, force);

    // Revalidate container list
    await mutate();

    return container;
  };

  /**
   * Refresh container list
   */
  const refresh = () => mutate();

  /**
   * Get labels for a container
   */
  const getLabels = async (username: string): Promise<Record<string, string>> => {
    if (!server) throw new Error('No server selected');
    const client = getClient(server);
    return client.getLabels(username);
  };

  /**
   * Set labels on a container
   */
  const setLabels = async (username: string, labels: Record<string, string>): Promise<Record<string, string>> => {
    if (!server) throw new Error('No server selected');
    const client = getClient(server);
    const result = await client.setLabels(username, labels);
    // Revalidate container list to show updated labels
    await mutate();
    return result;
  };

  /**
   * Remove a label from a container
   */
  const removeLabel = async (username: string, key: string): Promise<Record<string, string>> => {
    if (!server) throw new Error('No server selected');
    const client = getClient(server);
    const result = await client.removeLabel(username, key);
    // Revalidate container list to show updated labels
    await mutate();
    return result;
  };

  /**
   * Resize a container's resources (CPU, memory, disk)
   */
  const resizeContainer = async (
    username: string,
    resources: { cpu?: string; memory?: string; disk?: string }
  ) => {
    if (!server) throw new Error('No server selected');

    const client = getClient(server);
    const container = await client.resizeContainer(username, resources);

    // Revalidate container list
    await mutate();

    return container;
  };

  return {
    containers: data || [],
    systemInfo: systemInfo || null,
    isLoading,
    error,
    createContainer,
    deleteContainer,
    startContainer,
    stopContainer,
    resizeContainer,
    getLabels,
    setLabels,
    removeLabel,
    refresh,
    // Event stream status
    eventStatus,
    reconnectEvents: reconnect,
  };
}
