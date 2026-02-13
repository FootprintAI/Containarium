/**
 * Event types from the backend
 */
export type EventType =
  | 'EVENT_TYPE_UNSPECIFIED'
  | 'EVENT_TYPE_CONTAINER_CREATED'
  | 'EVENT_TYPE_CONTAINER_DELETED'
  | 'EVENT_TYPE_CONTAINER_STARTED'
  | 'EVENT_TYPE_CONTAINER_STOPPED'
  | 'EVENT_TYPE_CONTAINER_STATE_CHANGED'
  | 'EVENT_TYPE_APP_DEPLOYED'
  | 'EVENT_TYPE_APP_DELETED'
  | 'EVENT_TYPE_APP_STARTED'
  | 'EVENT_TYPE_APP_STOPPED'
  | 'EVENT_TYPE_APP_STATE_CHANGED'
  | 'EVENT_TYPE_ROUTE_ADDED'
  | 'EVENT_TYPE_ROUTE_DELETED'
  | 'EVENT_TYPE_METRICS_UPDATE';

/**
 * Resource types from the backend
 */
export type ResourceType =
  | 'RESOURCE_TYPE_UNSPECIFIED'
  | 'RESOURCE_TYPE_CONTAINER'
  | 'RESOURCE_TYPE_APP'
  | 'RESOURCE_TYPE_ROUTE'
  | 'RESOURCE_TYPE_METRICS';

/**
 * Container event payload
 */
export interface ContainerEventPayload {
  container?: {
    name: string;
    username: string;
    state: string;
    ipAddress?: string;
    cpu?: string;
    memory?: string;
    disk?: string;
    image?: string;
    dockerEnabled?: boolean;
  };
  previousState?: string;
}

/**
 * App event payload
 */
export interface AppEventPayload {
  app?: {
    id: string;
    name: string;
    username: string;
    containerName: string;
    subdomain: string;
    fullDomain: string;
    port: number;
    state: string;
  };
  previousState?: string;
}

/**
 * Route event payload
 */
export interface RouteEventPayload {
  route?: {
    subdomain: string;
    fullDomain: string;
    containerIp: string;
    port: number;
    active: boolean;
    appId?: string;
    appName?: string;
  };
}

/**
 * Metrics event payload
 */
export interface MetricsEventPayload {
  metrics: Array<{
    name: string;
    cpuUsageSeconds: number;
    memoryUsageBytes: number;
    memoryPeakBytes: number;
    diskUsageBytes: number;
    networkRxBytes: number;
    networkTxBytes: number;
    processCount: number;
  }>;
}

/**
 * Server-sent event from the backend
 */
export interface ServerEvent {
  id: string;
  type: EventType;
  resourceType: ResourceType;
  resourceId: string;
  timestamp: string;
  containerEvent?: ContainerEventPayload;
  appEvent?: AppEventPayload;
  routeEvent?: RouteEventPayload;
  metricsEvent?: MetricsEventPayload;
}

/**
 * Connection status for SSE
 */
export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

/**
 * Options for event stream subscription
 */
export interface EventStreamOptions {
  resourceTypes?: ResourceType[];
  includeMetrics?: boolean;
  metricsIntervalSeconds?: number;
  onEvent?: (event: ServerEvent) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
}

/**
 * Helper function to check if event is container-related
 */
export function isContainerEvent(event: ServerEvent): boolean {
  return event.resourceType === 'RESOURCE_TYPE_CONTAINER';
}

/**
 * Helper function to check if event is app-related
 */
export function isAppEvent(event: ServerEvent): boolean {
  return event.resourceType === 'RESOURCE_TYPE_APP';
}

/**
 * Helper function to check if event is route-related
 */
export function isRouteEvent(event: ServerEvent): boolean {
  return event.resourceType === 'RESOURCE_TYPE_ROUTE';
}

/**
 * Helper function to check if event is metrics-related
 */
export function isMetricsEvent(event: ServerEvent): boolean {
  return event.resourceType === 'RESOURCE_TYPE_METRICS';
}
