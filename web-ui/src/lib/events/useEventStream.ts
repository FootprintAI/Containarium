'use client';

import { useEffect, useRef, useCallback, useState, useMemo } from 'react';
import { Server } from '@/src/types/server';
import {
  ServerEvent,
  ConnectionStatus,
  EventStreamOptions,
} from '@/src/types/events';

// Grace period before showing error status (ms)
// This prevents UI flicker during expected reconnections
const ERROR_GRACE_PERIOD_MS = 5000;

// Max reconnect attempts before showing persistent error
const MAX_SILENT_RECONNECTS = 3;

// Global connection manager to share SSE connections
const connectionManager = new Map<string, {
  eventSource: EventSource;
  listeners: Set<(event: ServerEvent) => void>;
  status: ConnectionStatus;
  reconnectTimeout: NodeJS.Timeout | null;
  reconnectAttempts: number;
  lastConnectedTime: number;
}>();

/**
 * Get a unique key for a server connection
 */
function getConnectionKey(server: Server): string {
  return `${server.id}-${server.endpoint}`;
}

/**
 * Build SSE URL for a server
 */
function buildEventUrl(server: Server): string {
  // Normalize base URL - the endpoint already includes /v1
  let baseUrl = server.endpoint.trim();

  // Remove trailing slashes
  while (baseUrl.endsWith('/')) {
    baseUrl = baseUrl.slice(0, -1);
  }

  // Build URL - endpoint should be like https://example.com/v1
  // We append /events/subscribe to get https://example.com/v1/events/subscribe
  const fullUrl = `${baseUrl}/events/subscribe`;
  const url = new URL(fullUrl);

  url.searchParams.set('token', server.token);
  // Subscribe to all resource types
  url.searchParams.append('resourceTypes', 'CONTAINER');
  url.searchParams.append('resourceTypes', 'APP');
  url.searchParams.append('resourceTypes', 'ROUTE');

  return url.toString();
}

/**
 * Get or create a shared SSE connection for a server
 */
function getOrCreateConnection(
  server: Server,
  onStatusChange: (status: ConnectionStatus) => void
): { addListener: (fn: (event: ServerEvent) => void) => void; removeListener: (fn: (event: ServerEvent) => void) => void } {
  const key = getConnectionKey(server);

  let conn = connectionManager.get(key);

  if (!conn) {
    const url = buildEventUrl(server);
    const eventSource = new EventSource(url);

    conn = {
      eventSource,
      listeners: new Set(),
      status: 'connecting' as ConnectionStatus,
      reconnectTimeout: null,
      reconnectAttempts: 0,
      lastConnectedTime: 0,
    };

    connectionManager.set(key, conn);

    // Handle connection open
    eventSource.onopen = () => {
      const c = connectionManager.get(key);
      if (c) {
        c.status = 'connected';
        c.reconnectAttempts = 0;
        c.lastConnectedTime = Date.now();
        onStatusChange('connected');
      }
    };

    // Handle connection error
    eventSource.onerror = () => {
      const c = connectionManager.get(key);
      if (c) {
        const timeSinceConnected = Date.now() - c.lastConnectedTime;
        const isExpectedDisconnect = timeSinceConnected > 0 && timeSinceConnected < 60000; // Disconnected within 60s of connecting

        // Only show error status after grace period or multiple failures
        if (c.reconnectAttempts >= MAX_SILENT_RECONNECTS ||
            (timeSinceConnected > ERROR_GRACE_PERIOD_MS && !isExpectedDisconnect)) {
          c.status = 'error';
          onStatusChange('error');
        }
        // Otherwise keep current status (connected) during quick reconnect

        // Auto-reconnect: immediate for first few attempts, then exponential backoff
        let delay: number;
        if (c.reconnectAttempts < MAX_SILENT_RECONNECTS) {
          delay = 100; // Quick reconnect for expected disconnects
        } else {
          delay = Math.min(1000 * Math.pow(2, c.reconnectAttempts - MAX_SILENT_RECONNECTS), 30000);
        }
        c.reconnectAttempts++;

        if (c.reconnectTimeout) {
          clearTimeout(c.reconnectTimeout);
        }

        c.reconnectTimeout = setTimeout(() => {
          const current = connectionManager.get(key);
          if (current && current.eventSource.readyState === EventSource.CLOSED) {
            // Remove old connection and create new one
            connectionManager.delete(key);
            if (current.listeners.size > 0) {
              // Reconnect with existing listeners
              const newConn = getOrCreateConnection(server, onStatusChange);
              current.listeners.forEach(listener => {
                newConn.addListener(listener);
              });
            }
          }
        }, delay);
      }
    };

    // Handle connected event
    eventSource.addEventListener('connected', () => {
      // Connection confirmed - already handled by onopen
    });

    // Handle all event types
    const eventTypes = [
      'container_created',
      'container_deleted',
      'container_started',
      'container_stopped',
      'container_state_changed',
      'app_deployed',
      'app_deleted',
      'app_started',
      'app_stopped',
      'app_state_changed',
      'route_added',
      'route_deleted',
      'metrics_update',
    ];

    eventTypes.forEach((eventType) => {
      eventSource.addEventListener(eventType, (event) => {
        try {
          const data: ServerEvent = JSON.parse((event as MessageEvent).data);
          const c = connectionManager.get(key);
          if (c) {
            c.listeners.forEach(listener => listener(data));
          }
        } catch (e) {
          console.error(`Failed to parse ${eventType} event:`, e);
        }
      });
    });
  }

  return {
    addListener: (fn: (event: ServerEvent) => void) => {
      const c = connectionManager.get(key);
      if (c) {
        c.listeners.add(fn);
      }
    },
    removeListener: (fn: (event: ServerEvent) => void) => {
      const c = connectionManager.get(key);
      if (c) {
        c.listeners.delete(fn);
        // Close connection if no more listeners
        if (c.listeners.size === 0) {
          if (c.reconnectTimeout) {
            clearTimeout(c.reconnectTimeout);
          }
          c.eventSource.close();
          connectionManager.delete(key);
        }
      }
    },
  };
}

/**
 * Hook for subscribing to server-sent events from the backend.
 * Uses a shared connection per server to avoid multiple connections.
 */
export function useEventStream(
  server: Server | null,
  options: EventStreamOptions = {}
) {
  const { onEvent } = options;

  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const listenerRef = useRef<((event: ServerEvent) => void) | null>(null);
  const connectionRef = useRef<ReturnType<typeof getOrCreateConnection> | null>(null);

  // Memoize the event handler
  const handleEvent = useCallback(
    (event: ServerEvent) => {
      onEvent?.(event);
    },
    [onEvent]
  );

  // Store the latest handler in a ref
  useEffect(() => {
    listenerRef.current = handleEvent;
  }, [handleEvent]);

  // Stable listener that uses the ref
  const stableListener = useMemo(() => {
    return (event: ServerEvent) => {
      listenerRef.current?.(event);
    };
  }, []);

  useEffect(() => {
    if (!server) {
      setStatus('disconnected');
      return;
    }

    const conn = getOrCreateConnection(server, setStatus);
    connectionRef.current = conn;
    conn.addListener(stableListener);

    return () => {
      conn.removeListener(stableListener);
    };
  }, [server, stableListener]);

  const reconnect = useCallback(() => {
    if (!server) return;

    const key = getConnectionKey(server);
    const conn = connectionManager.get(key);
    if (conn) {
      if (conn.reconnectTimeout) {
        clearTimeout(conn.reconnectTimeout);
      }
      conn.eventSource.close();
      connectionManager.delete(key);
    }

    // Force reconnection on next render
    setStatus('connecting');
    const newConn = getOrCreateConnection(server, setStatus);
    connectionRef.current = newConn;
    newConn.addListener(stableListener);
  }, [server, stableListener]);

  return {
    status,
    reconnect,
  };
}

/**
 * Helper hook to filter events by resource type
 */
export function useFilteredEventStream(
  server: Server | null,
  resourceType: string,
  options: Omit<EventStreamOptions, 'resourceTypes'> = {}
) {
  const filteredOnEvent = useCallback(
    (event: ServerEvent) => {
      if (event.resourceType === resourceType) {
        options.onEvent?.(event);
      }
    },
    [resourceType, options]
  );

  return useEventStream(server, {
    ...options,
    onEvent: filteredOnEvent,
  });
}
