import axios, { AxiosInstance, AxiosError } from 'axios';
import { Container, ContainerMetrics, CreateContainerRequest, CreateContainerResponse, ListContainersResponse, MetricsResponse, SystemInfo } from '@/src/types/container';
import { Server } from '@/src/types/server';
import { App, NetworkACL, ProxyRoute, NetworkTopology, ACLPresetInfo, DNSRecord, PassthroughRoute } from '@/src/types/app';
import { Connection, ConnectionSummary, HistoricalConnection, TrafficAggregate, GetConnectionsResponse, GetConnectionSummaryResponse, QueryTrafficHistoryResponse, GetTrafficAggregatesResponse } from '@/src/types/traffic';

/**
 * API error response
 */
export interface APIError {
  error: string;
  code: number;
}

/**
 * Normalize endpoint URL to ensure it has a protocol
 */
function normalizeEndpoint(endpoint: string): string {
  let url = endpoint.trim();
  // Add http:// if no protocol is specified
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'http://' + url;
  }
  // Remove trailing slash
  if (url.endsWith('/')) {
    url = url.slice(0, -1);
  }
  return url;
}

/**
 * Sanitize token by removing all whitespace (spaces, newlines, etc.)
 */
function sanitizeToken(token: string): string {
  return token.replace(/\s+/g, '');
}

/**
 * Map API container state to frontend state
 */
function mapContainerState(apiState: string): string {
  const stateMap: Record<string, string> = {
    'CONTAINER_STATE_RUNNING': 'Running',
    'CONTAINER_STATE_STOPPED': 'Stopped',
    'CONTAINER_STATE_FROZEN': 'Frozen',
    'CONTAINER_STATE_CREATING': 'Creating',
    'CONTAINER_STATE_ERROR': 'Error',
    'CONTAINER_STATE_UNKNOWN': 'Unknown',
    'CONTAINER_STATE_UNSPECIFIED': 'Unknown',
  };
  return stateMap[apiState] || apiState;
}

/**
 * Transform API container response to frontend Container type
 */
function transformContainer(apiContainer: Record<string, unknown>): Container {
  return {
    name: (apiContainer.name as string) || '',
    username: (apiContainer.username as string) || '',
    state: mapContainerState((apiContainer.state as string) || '') as Container['state'],
    ipAddress: ((apiContainer.network as Record<string, unknown>)?.ipAddress as string) || '',
    cpu: ((apiContainer.resources as Record<string, unknown>)?.cpu as string) || '',
    memory: ((apiContainer.resources as Record<string, unknown>)?.memory as string) || '',
    disk: ((apiContainer.resources as Record<string, unknown>)?.disk as string) || '',
    gpu: ((apiContainer.resources as Record<string, unknown>)?.gpu as string) || '',
    image: (apiContainer.image as string) || '',
    podmanEnabled: (apiContainer.podmanEnabled as boolean) || false,
    stack: (apiContainer.stack as string) || '',
    createdAt: (apiContainer.createdAt as string) || '',
    updatedAt: (apiContainer.updatedAt as string) || '',
    labels: (apiContainer.labels as Record<string, string>) || {},
    sshKeys: (apiContainer.sshKeys as string[]) || [],
  };
}

/**
 * Create an API client for a specific server
 */
export function createAPIClient(server: Server): AxiosInstance {
  const baseURL = normalizeEndpoint(server.endpoint);
  const token = sanitizeToken(server.token);
  const client = axios.create({
    baseURL,
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json',
    },
    timeout: 30000,
  });

  // Response interceptor for error handling
  client.interceptors.response.use(
    response => response,
    (error: AxiosError<APIError>) => {
      if (error.response?.status === 401) {
        console.error('Authentication failed for server:', server.name);
      }
      return Promise.reject(error);
    }
  );

  return client;
}

/**
 * Containarium API client
 */
export class ContaineriumClient {
  private client: AxiosInstance;
  private server: Server;

  constructor(server: Server) {
    this.server = server;
    this.client = createAPIClient(server);
  }

  /**
   * Test connection to the server
   */
  async testConnection(): Promise<boolean> {
    try {
      await this.getSystemInfo();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get system information
   */
  async getSystemInfo(): Promise<SystemInfo> {
    const response = await this.client.get('/system/info');
    return response.data.info || response.data;
  }

  /**
   * List all containers
   */
  async listContainers(): Promise<Container[]> {
    const response = await this.client.get('/containers');
    const containers = response.data.containers || [];
    return containers.map((c: Record<string, unknown>) => transformContainer(c));
  }

  /**
   * Get a specific container
   */
  async getContainer(username: string): Promise<Container> {
    const response = await this.client.get('/containers/' + username);
    const container = response.data.container || response.data;
    return transformContainer(container);
  }

  /**
   * Create a new container with async support
   * When async=true, returns immediately with CREATING state
   */
  async createContainer(request: CreateContainerRequest, async: boolean = true): Promise<CreateContainerResponse> {
    const response = await this.client.post<CreateContainerResponse>('/containers', {
      username: request.username,
      resources: request.resources,
      ssh_keys: request.sshKeys,
      labels: request.labels,
      image: request.image,
      enable_podman: request.enablePodman ?? true,
      stack: request.stack || '',
      static_ip: request.staticIp || '',
      async: async,
    }, {
      timeout: async ? 30000 : 300000, // 30s for async, 5min for sync
    });
    return response.data;
  }

  /**
   * Poll container until it reaches a final state (Running, Stopped, or Error)
   * Throws an error if the container ends up in Error state
   */
  async waitForContainer(
    username: string,
    onProgress?: (state: string, message: string) => void,
    maxAttempts: number = 60,
    intervalMs: number = 5000
  ): Promise<Container> {
    const finalStates = ['Running', 'Stopped', 'Error'];

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const container = await this.getContainer(username);

        if (onProgress) {
          onProgress(container.state, `Container is ${container.state.toLowerCase()}...`);
        }

        if (finalStates.includes(container.state)) {
          // Throw an error if container ended up in Error state
          if (container.state === 'Error') {
            throw new Error('Container creation failed. Check server logs for details.');
          }
          return container;
        }

        // Wait before next poll
        await new Promise(resolve => setTimeout(resolve, intervalMs));
      } catch (err) {
        // If it's our own error about container failure, re-throw it
        if (err instanceof Error && err.message.includes('Container creation failed')) {
          throw err;
        }
        // Container might not exist yet, keep polling
        if (onProgress) {
          onProgress('Creating', 'Waiting for container to be created...');
        }
        await new Promise(resolve => setTimeout(resolve, intervalMs));
      }
    }

    throw new Error('Timeout waiting for container to be ready');
  }

  /**
   * Delete a container
   */
  async deleteContainer(username: string, force: boolean = false): Promise<void> {
    await this.client.delete('/containers/' + username, {
      params: { force },
    });
  }

  /**
   * Start a container
   */
  async startContainer(username: string): Promise<Container> {
    const response = await this.client.post('/containers/' + username + '/start', {});
    const container = response.data.container || response.data;
    return transformContainer(container);
  }

  /**
   * Stop a container
   */
  async stopContainer(username: string, force: boolean = false): Promise<Container> {
    const response = await this.client.post('/containers/' + username + '/stop', { force });
    const container = response.data.container || response.data;
    return transformContainer(container);
  }

  /**
   * Resize container resources (CPU, memory, disk)
   * All parameters are optional - only specified values will be changed
   * Note: Disk can only be increased, not decreased
   */
  async resizeContainer(
    username: string,
    resources: { cpu?: string; memory?: string; disk?: string }
  ): Promise<Container> {
    const response = await this.client.put('/containers/' + username + '/resize', {
      cpu: resources.cpu || '',
      memory: resources.memory || '',
      disk: resources.disk || '',
    });
    const container = response.data.container || response.data;
    return transformContainer(container);
  }

  /**
   * Get metrics for all containers or a specific container
   */
  async getMetrics(username?: string): Promise<ContainerMetrics[]> {
    const params = username ? { username } : {};
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const response = await this.client.get<{ metrics?: any[] }>('/metrics', { params });
    const metrics = response.data.metrics || [];
    // Parse string numbers to actual numbers (API may return strings)
    return metrics.map((m) => ({
      name: String(m.name || ''),
      cpuUsageSeconds: Number(m.cpuUsageSeconds) || 0,
      memoryUsageBytes: Number(m.memoryUsageBytes) || 0,
      memoryPeakBytes: Number(m.memoryPeakBytes) || 0,
      diskUsageBytes: Number(m.diskUsageBytes) || 0,
      networkRxBytes: Number(m.networkRxBytes) || 0,
      networkTxBytes: Number(m.networkTxBytes) || 0,
      processCount: Number(m.processCount) || 0,
    }));
  }

  // ============================================
  // App Management Methods
  // ============================================

  /**
   * List all apps for a user
   */
  async listApps(username?: string): Promise<App[]> {
    const params = username ? { username } : {};
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const response = await this.client.get<{ apps?: any[] }>('/apps', { params });
    return response.data.apps || [];
  }

  /**
   * Get a specific app
   */
  async getApp(username: string, appName: string): Promise<App> {
    const response = await this.client.get(`/apps/${username}/${appName}`);
    return response.data.app || response.data;
  }

  /**
   * Stop an app
   */
  async stopApp(username: string, appName: string): Promise<App> {
    const response = await this.client.post(`/apps/${username}/${appName}/stop`, {});
    return response.data.app || response.data;
  }

  /**
   * Start an app
   */
  async startApp(username: string, appName: string): Promise<App> {
    const response = await this.client.post(`/apps/${username}/${appName}/start`, {});
    return response.data.app || response.data;
  }

  /**
   * Restart an app
   */
  async restartApp(username: string, appName: string): Promise<App> {
    const response = await this.client.post(`/apps/${username}/${appName}/restart`, {});
    return response.data.app || response.data;
  }

  /**
   * Delete an app
   */
  async deleteApp(username: string, appName: string, removeData: boolean = false): Promise<void> {
    await this.client.delete(`/apps/${username}/${appName}`, {
      params: { removeData },
    });
  }

  /**
   * Get app logs
   */
  async getAppLogs(username: string, appName: string, tailLines: number = 100): Promise<string[]> {
    const response = await this.client.get(`/apps/${username}/${appName}/logs`, {
      params: { tailLines },
    });
    return response.data.logLines || [];
  }

  // ============================================
  // Network Management Methods
  // ============================================

  /**
   * Get all proxy routes
   */
  async getRoutes(username?: string): Promise<ProxyRoute[]> {
    const params = username ? { username } : {};
    const response = await this.client.get<{ routes?: ProxyRoute[] }>('/network/routes', { params });
    return response.data.routes || [];
  }

  /**
   * Add a new proxy route
   * @param protocol - Route protocol: 'ROUTE_PROTOCOL_HTTP' (default) or 'ROUTE_PROTOCOL_GRPC'
   */
  async addRoute(domain: string, targetIp: string, targetPort: number, protocol?: string): Promise<ProxyRoute> {
    const response = await this.client.post<{ route?: ProxyRoute }>('/network/routes', {
      domain,
      target_ip: targetIp,
      target_port: targetPort,
      protocol: protocol || 'ROUTE_PROTOCOL_HTTP',
    });
    return response.data.route || {
      subdomain: domain,
      fullDomain: domain,
      containerIp: targetIp,
      port: targetPort,
      active: true,
      protocol: protocol as any || 'ROUTE_PROTOCOL_HTTP',
    };
  }

  /**
   * Delete a proxy route
   */
  async deleteRoute(domain: string): Promise<void> {
    await this.client.delete(`/network/routes/${encodeURIComponent(domain)}`);
  }

  /**
   * Update a proxy route (enable/disable or modify)
   * @param domain - Domain name (identifies the route)
   * @param options - Update options (active to toggle, targetIp/targetPort to update target)
   */
  async updateRoute(
    domain: string,
    options: {
      active?: boolean;
      targetIp?: string;
      targetPort?: number;
      protocol?: string;
    }
  ): Promise<ProxyRoute> {
    const response = await this.client.put<{ route?: ProxyRoute }>(
      `/network/routes/${encodeURIComponent(domain)}`,
      {
        domain,
        target_ip: options.targetIp,
        target_port: options.targetPort,
        protocol: options.protocol,
        active: options.active,
      }
    );
    return response.data.route || {
      subdomain: domain,
      fullDomain: domain,
      containerIp: options.targetIp || '',
      port: options.targetPort || 0,
      active: options.active ?? true,
      protocol: options.protocol as any || 'ROUTE_PROTOCOL_HTTP',
    };
  }

  /**
   * Get passthrough routes (TCP/UDP port forwarding)
   */
  async getPassthroughRoutes(): Promise<PassthroughRoute[]> {
    const response = await this.client.get<{ routes?: PassthroughRoute[] }>('/network/passthrough');
    return (response.data.routes || []).map(r => ({
      externalPort: r.externalPort || (r as any).external_port,
      targetIp: r.targetIp || (r as any).target_ip,
      targetPort: r.targetPort || (r as any).target_port,
      protocol: r.protocol,
      active: r.active,
      containerName: r.containerName || (r as any).container_name,
      description: r.description,
    }));
  }

  /**
   * Add a passthrough route (TCP/UDP port forwarding)
   */
  async addPassthroughRoute(
    externalPort: number,
    targetIp: string,
    targetPort: number,
    protocol: string = 'ROUTE_PROTOCOL_TCP',
    containerName?: string,
    description?: string
  ): Promise<PassthroughRoute> {
    const response = await this.client.post<{ route?: PassthroughRoute }>('/network/passthrough', {
      external_port: externalPort,
      target_ip: targetIp,
      target_port: targetPort,
      protocol,
      container_name: containerName,
      description,
    });
    const r = response.data.route;
    return r ? {
      externalPort: r.externalPort || (r as any).external_port,
      targetIp: r.targetIp || (r as any).target_ip,
      targetPort: r.targetPort || (r as any).target_port,
      protocol: r.protocol,
      active: r.active,
      containerName: r.containerName || (r as any).container_name,
      description: r.description,
    } : {
      externalPort,
      targetIp,
      targetPort,
      protocol: protocol as any,
      active: true,
      containerName,
      description,
    };
  }

  /**
   * Delete a passthrough route
   */
  async deletePassthroughRoute(externalPort: number, protocol: string = 'ROUTE_PROTOCOL_TCP'): Promise<void> {
    await this.client.delete(`/network/passthrough/${externalPort}`, {
      params: { protocol },
    });
  }

  /**
   * Update a passthrough route (enable/disable or modify)
   * @param externalPort - External port (identifies the route)
   * @param protocol - Protocol (TCP/UDP, identifies the route)
   * @param options - Update options
   */
  async updatePassthroughRoute(
    externalPort: number,
    protocol: string,
    options: {
      active?: boolean;
      targetIp?: string;
      targetPort?: number;
      containerName?: string;
      description?: string;
    }
  ): Promise<PassthroughRoute> {
    const response = await this.client.put<{ route?: PassthroughRoute }>(
      `/network/passthrough/${externalPort}`,
      {
        external_port: externalPort,
        protocol,
        target_ip: options.targetIp,
        target_port: options.targetPort,
        container_name: options.containerName,
        description: options.description,
        active: options.active,
      }
    );
    const r = response.data.route;
    return r ? {
      externalPort: r.externalPort || (r as any).external_port,
      targetIp: r.targetIp || (r as any).target_ip,
      targetPort: r.targetPort || (r as any).target_port,
      protocol: r.protocol,
      active: r.active,
      containerName: r.containerName || (r as any).container_name,
      description: r.description,
    } : {
      externalPort,
      targetIp: options.targetIp || '',
      targetPort: options.targetPort || 0,
      protocol: protocol as any,
      active: options.active ?? true,
      containerName: options.containerName,
      description: options.description,
    };
  }

  /**
   * Get ACL for a container (DevBox)
   */
  async getContainerACL(username: string): Promise<NetworkACL> {
    const response = await this.client.get(`/v1/containers/${username}/acl`);
    return response.data.acl || response.data;
  }

  /**
   * Update ACL for a container (DevBox)
   */
  async updateContainerACL(
    username: string,
    preset: string,
    ingressRules?: unknown[],
    egressRules?: unknown[]
  ): Promise<NetworkACL> {
    const response = await this.client.put(`/v1/containers/${username}/acl`, {
      username,
      preset,
      ingressRules,
      egressRules,
    });
    return response.data.acl || response.data;
  }

  /**
   * Get network topology
   */
  async getNetworkTopology(includeStopped: boolean = false): Promise<NetworkTopology> {
    const response = await this.client.get<{ topology?: NetworkTopology }>('/network/topology', {
      params: { includeStopped },
    });
    return response.data.topology || { nodes: [], edges: [], networkCidr: '', gatewayIp: '' };
  }

  /**
   * Get available ACL presets
   */
  async getACLPresets(): Promise<ACLPresetInfo[]> {
    const response = await this.client.get<{ presets?: ACLPresetInfo[] }>('/network/acl-presets');
    return response.data.presets || [];
  }

  /**
   * Get DNS records for domain suggestions
   */
  async getDNSRecords(): Promise<{ records: DNSRecord[]; baseDomain: string }> {
    const response = await this.client.get<{ records?: DNSRecord[]; baseDomain?: string }>('/network/dns-records');
    return {
      records: response.data.records || [],
      baseDomain: response.data.baseDomain || '',
    };
  }

  // ============================================
  // Label Management Methods
  // ============================================

  /**
   * Get labels for a container
   */
  async getLabels(username: string): Promise<Record<string, string>> {
    const response = await this.client.get<{ labels?: Record<string, string> }>(`/containers/${username}/labels`);
    return response.data.labels || {};
  }

  /**
   * Set labels on a container (overwrites existing labels with same keys)
   */
  async setLabels(username: string, labels: Record<string, string>): Promise<Record<string, string>> {
    const response = await this.client.put<{ labels?: Record<string, string> }>(`/containers/${username}/labels`, {
      labels,
    });
    return response.data.labels || {};
  }

  /**
   * Remove a label from a container
   */
  async removeLabel(username: string, key: string): Promise<Record<string, string>> {
    const response = await this.client.delete<{ labels?: Record<string, string> }>(`/containers/${username}/labels/${key}`);
    return response.data.labels || {};
  }

  // ============================================
  // Traffic Monitoring Methods
  // ============================================

  /**
   * Get active connections for a container
   */
  async getConnections(containerName: string, options?: {
    protocol?: string;
    destIpPrefix?: string;
    destPort?: number;
    limit?: number;
  }): Promise<GetConnectionsResponse> {
    const params: Record<string, unknown> = {};
    if (options?.protocol) params.protocol = options.protocol;
    if (options?.destIpPrefix) params.destIpPrefix = options.destIpPrefix;
    if (options?.destPort) params.destPort = options.destPort;
    if (options?.limit) params.limit = options.limit;

    const response = await this.client.get<GetConnectionsResponse>(
      `/containers/${containerName}/connections`,
      { params }
    );
    return {
      connections: response.data.connections || [],
      totalCount: response.data.totalCount || 0,
    };
  }

  /**
   * Get connection summary for a container
   */
  async getConnectionSummary(containerName: string): Promise<ConnectionSummary> {
    const response = await this.client.get<GetConnectionSummaryResponse>(
      `/containers/${containerName}/connections/summary`
    );
    return response.data.summary || {
      containerName,
      activeConnections: 0,
      tcpConnections: 0,
      udpConnections: 0,
      totalBytesSent: 0,
      totalBytesReceived: 0,
      topDestinations: [],
    };
  }

  /**
   * Query traffic history for a container
   */
  async getTrafficHistory(containerName: string, options: {
    startTime: string;
    endTime: string;
    destIp?: string;
    destPort?: number;
    offset?: number;
    limit?: number;
  }): Promise<QueryTrafficHistoryResponse> {
    const params: Record<string, unknown> = {
      startTime: options.startTime,
      endTime: options.endTime,
    };
    if (options.destIp) params.destIp = options.destIp;
    if (options.destPort) params.destPort = options.destPort;
    if (options.offset) params.offset = options.offset;
    if (options.limit) params.limit = options.limit;

    const response = await this.client.get<QueryTrafficHistoryResponse>(
      `/containers/${containerName}/traffic/history`,
      { params }
    );
    return {
      connections: response.data.connections || [],
      totalCount: response.data.totalCount || 0,
    };
  }

  /**
   * Get traffic aggregates for a container
   */
  async getTrafficAggregates(containerName: string, options: {
    startTime: string;
    endTime: string;
    interval?: string;
    groupByDestIp?: boolean;
    groupByDestPort?: boolean;
  }): Promise<TrafficAggregate[]> {
    const params: Record<string, unknown> = {
      startTime: options.startTime,
      endTime: options.endTime,
    };
    if (options.interval) params.interval = options.interval;
    if (options.groupByDestIp) params.groupByDestIp = options.groupByDestIp;
    if (options.groupByDestPort) params.groupByDestPort = options.groupByDestPort;

    const response = await this.client.get<GetTrafficAggregatesResponse>(
      `/containers/${containerName}/traffic/aggregates`,
      { params }
    );
    return response.data.aggregates || [];
  }
}

/**
 * Create a client instance for a server
 */
export function getClient(server: Server): ContaineriumClient {
  return new ContaineriumClient(server);
}
