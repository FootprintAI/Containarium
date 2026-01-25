'use client';

import useSWR from 'swr';
import { NetworkACL, ProxyRoute, NetworkTopology, ACLPresetInfo } from '@/src/types/app';
import { Server } from '@/src/types/server';
import { getClient } from '@/src/lib/api/client';

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
      refreshInterval: 15000,
      revalidateOnFocus: true,
      dedupingInterval: 5000,
    }
  );

  return {
    routes: data || [],
    isLoading,
    error,
    refresh: () => mutate(),
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
      refreshInterval: 15000,
      revalidateOnFocus: true,
      dedupingInterval: 5000,
    }
  );

  return {
    topology: data || { nodes: [], edges: [], networkCidr: '', gatewayIp: '' },
    isLoading,
    error,
    refresh: () => mutate(),
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
