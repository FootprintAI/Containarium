import axios, { AxiosInstance, AxiosError } from 'axios';
import { Container, ContainerMetrics, CreateContainerRequest, CreateContainerResponse, ListContainersResponse, MetricsResponse, SystemInfo } from '@/src/types/container';
import { Server } from '@/src/types/server';
import { App, NetworkACL, ProxyRoute, NetworkTopology, ACLPresetInfo } from '@/src/types/app';

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
    dockerEnabled: (apiContainer.dockerEnabled as boolean) || false,
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
      enable_docker: request.enableDocker ?? true,
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
}

/**
 * Create a client instance for a server
 */
export function getClient(server: Server): ContaineriumClient {
  return new ContaineriumClient(server);
}
