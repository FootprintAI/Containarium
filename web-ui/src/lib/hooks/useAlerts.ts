'use client';

import useSWR from 'swr';
import { Server } from '@/src/types/server';
import { AlertRulesResponse, AlertingInfoResponse, WebhookDeliveriesResponse } from '@/src/types/alerts';
import { getClient } from '@/src/lib/api/client';

/**
 * Hook for fetching alert rules
 */
export function useAlerts(server: Server | null) {
  const fetcher = async (): Promise<AlertRulesResponse> => {
    if (!server) throw new Error('No server');
    const client = getClient(server);
    return client.listAlertRules();
  };

  const swrKey = server ? `alert-rules-${server.id}` : null;

  const { data, error, isLoading, mutate } = useSWR<AlertRulesResponse>(
    swrKey,
    fetcher,
    {
      refreshInterval: 30000,
      revalidateOnFocus: true,
      dedupingInterval: 5000,
    }
  );

  return {
    rules: data?.rules || [],
    isLoading,
    error,
    refresh: () => mutate(),
  };
}

/**
 * Hook for fetching alerting system info
 */
export function useAlertingInfo(server: Server | null) {
  const fetcher = async (): Promise<AlertingInfoResponse> => {
    if (!server) throw new Error('No server');
    const client = getClient(server);
    return client.getAlertingInfo();
  };

  const swrKey = server ? `alerting-info-${server.id}` : null;

  const { data, error, isLoading, mutate } = useSWR<AlertingInfoResponse>(
    swrKey,
    fetcher,
    {
      refreshInterval: 60000,
      revalidateOnFocus: true,
      dedupingInterval: 10000,
    }
  );

  return {
    info: data || null,
    isLoading,
    error,
    refresh: () => mutate(),
  };
}

/**
 * Hook for fetching webhook delivery history
 */
export function useWebhookDeliveries(server: Server | null) {
  const fetcher = async (): Promise<WebhookDeliveriesResponse> => {
    if (!server) throw new Error('No server');
    const client = getClient(server);
    return client.listWebhookDeliveries(50, 0);
  };

  const swrKey = server ? `webhook-deliveries-${server.id}` : null;

  const { data, error, isLoading, mutate } = useSWR<WebhookDeliveriesResponse>(
    swrKey,
    fetcher,
    {
      refreshInterval: 30000,
      revalidateOnFocus: true,
      dedupingInterval: 5000,
    }
  );

  return {
    deliveries: data?.deliveries || [],
    totalCount: data?.totalCount || 0,
    isLoading,
    error,
    refresh: () => mutate(),
  };
}

/**
 * Hook for fetching default (built-in) alert rules
 */
export function useDefaultAlertRules(server: Server | null) {
  const fetcher = async (): Promise<AlertRulesResponse> => {
    if (!server) throw new Error('No server');
    const client = getClient(server);
    return client.listDefaultAlertRules();
  };

  const swrKey = server ? `default-alert-rules-${server.id}` : null;

  const { data, error, isLoading } = useSWR<AlertRulesResponse>(
    swrKey,
    fetcher,
    {
      revalidateOnFocus: false,
      dedupingInterval: 60000,
    }
  );

  return {
    rules: data?.rules || [],
    isLoading,
    error,
  };
}
