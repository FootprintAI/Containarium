'use client';

import { useCallback } from 'react';
import useSWR from 'swr';
import { NetworkACL, ProxyRoute, NetworkTopology, ACLPresetInfo, DNSRecord } from '@/src/types/app';
import { Server } from '@/src/types/server';
import { getClient } from '@/src/lib/api/client';
import { useEventStream } from '@/src/lib/events/useEventStream';
import { ServerEvent, isRouteEvent } from '@/src/types/events';

/**
 * Hook for managing network routes
 */
export function useRoutes(server: Server | null, username?: string) {
  const fetcher = async (): Promise<ProxyRoute[]> => {
    if (!server) return [];
    const client = getClient(server);
    return client.getRoutes(username);
  };

  const swrKey = server ? `routes-${server.id}-${username || 'all'}` : null;

  const { data, error, isLoading, mutate } = useSWR<ProxyRoute[]>(
    swrKey,
    fetcher,
    {
      // No polling - rely on SSE for real-time updates
      refreshInterval: 0,
      revalidateOnFocus: true,
      dedupingInterval: 5000,
    }
  );

  // Handle route events from SSE
  const handleEvent = useCallback(
    (event: ServerEvent) => {
      if (!isRouteEvent(event)) return;

      // Revalidate route list on any route event
      mutate();
    },
    [mutate]
  );

  // Subscribe to route events via SSE
  const { status: eventStatus, reconnect } = useEventStream(server, {
    resourceTypes: ['RESOURCE_TYPE_ROUTE'],
    onEvent: handleEvent,
  });

  const addRoute = async (domain: string, targetIp: string, targetPort: number) => {
    if (!server) throw new Error('No server selected');
    const client = getClient(server);
    const route = await client.addRoute(domain, targetIp, targetPort);
    await mutate();
    return route;
  };

  const deleteRoute = async (domain: string) => {
    if (!server) throw new Error('No server selected');
    const client = getClient(server);
    await client.deleteRoute(domain);
    await mutate();
  };

  return {
    routes: data || [],
    isLoading,
    error,
    addRoute,
    deleteRoute,
    refresh: () => mutate(),
    // Event stream status
    eventStatus,
    reconnectEvents: reconnect,
  };
}

/**
 * Hook for managing network topology
 */
export function useNetworkTopology(server: Server | null, includeStopped: boolean = false) {
  const fetcher = async (): Promise<NetworkTopology> => {
    if (!server) return { nodes: [], edges: [], networkCidr: '', gatewayIp: '' };
    const client = getClient(server);
    return client.getNetworkTopology(includeStopped);
  };

  const swrKey = server ? `topology-${server.id}-${includeStopped}` : null;

  const { data, error, isLoading, mutate } = useSWR<NetworkTopology>(
    swrKey,
    fetcher,
    {
      // No polling - rely on SSE for real-time updates
      refreshInterval: 0,
      revalidateOnFocus: true,
      dedupingInterval: 5000,
    }
  );

  // Handle events that affect topology (containers and routes)
  const handleEvent = useCallback(
    () => {
      // Revalidate topology on any container or route event
      mutate();
    },
    [mutate]
  );

  // Subscribe to container and route events via SSE
  const { status: eventStatus, reconnect } = useEventStream(server, {
    resourceTypes: ['RESOURCE_TYPE_CONTAINER', 'RESOURCE_TYPE_ROUTE'],
    onEvent: handleEvent,
  });

  return {
    topology: data || { nodes: [], edges: [], networkCidr: '', gatewayIp: '' },
    isLoading,
    error,
    refresh: () => mutate(),
    // Event stream status
    eventStatus,
    reconnectEvents: reconnect,
  };
}

/**
 * Hook for managing ACL for a container (DevBox)
 * Firewall is applied at the container level, not per-app
 */
export function useContainerACL(server: Server | null, username: string) {
  const fetcher = async (): Promise<NetworkACL | null> => {
    if (!server || !username) return null;
    const client = getClient(server);
    return client.getContainerACL(username);
  };

  const swrKey = server && username ? `container-acl-${server.id}-${username}` : null;

  const { data, error, isLoading, mutate } = useSWR<NetworkACL | null>(
    swrKey,
    fetcher,
    {
      revalidateOnFocus: true,
      dedupingInterval: 5000,
    }
  );

  const updateACL = async (
    preset: string,
    ingressRules?: unknown[],
    egressRules?: unknown[]
  ) => {
    if (!server) throw new Error('No server selected');

    const client = getClient(server);
    const acl = await client.updateContainerACL(username, preset, ingressRules, egressRules);
    await mutate();
    return acl;
  };

  return {
    acl: data,
    isLoading,
    error,
    updateACL,
    refresh: () => mutate(),
  };
}

/**
 * @deprecated Use useContainerACL instead - ACL is now per-container, not per-app
 */
export function useACL(server: Server | null, username: string, _appName: string) {
  return useContainerACL(server, username);
}

/**
 * Hook for getting ACL presets
 */
export function useACLPresets(server: Server | null) {
  const fetcher = async (): Promise<ACLPresetInfo[]> => {
    if (!server) return [];
    const client = getClient(server);
    return client.getACLPresets();
  };

  const swrKey = server ? `acl-presets-${server.id}` : null;

  const { data, error, isLoading } = useSWR<ACLPresetInfo[]>(
    swrKey,
    fetcher,
    {
      revalidateOnFocus: false,
      dedupingInterval: 60000, // Presets don't change often
    }
  );

  return {
    presets: data || [],
    isLoading,
    error,
  };
}

/**
 * Hook for getting DNS records (domain suggestions)
 */
export function useDNSRecords(server: Server | null) {
  const fetcher = async (): Promise<{ records: DNSRecord[]; baseDomain: string }> => {
    if (!server) return { records: [], baseDomain: '' };
    const client = getClient(server);
    return client.getDNSRecords();
  };

  const swrKey = server ? `dns-records-${server.id}` : null;

  const { data, error, isLoading, mutate } = useSWR<{ records: DNSRecord[]; baseDomain: string }>(
    swrKey,
    fetcher,
    {
      revalidateOnFocus: false,
      dedupingInterval: 30000,
    }
  );

  return {
    records: data?.records || [],
    baseDomain: data?.baseDomain || '',
    isLoading,
    error,
    refresh: () => mutate(),
  };
}
