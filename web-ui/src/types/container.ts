/**
 * Container state enum
 */
export type ContainerState = 'Running' | 'Stopped' | 'Frozen' | 'Creating' | 'Error' | 'Unknown';

/**
 * Container information from Containarium API
 */
export interface Container {
  name: string;
  username: string;
  state: ContainerState;
  ipAddress: string;
  cpu: string;
  memory: string;
  disk: string;
  gpu: string;
  image: string;
  dockerEnabled: boolean;
  createdAt: string;
  updatedAt: string;
  labels: Record<string, string>;
  sshKeys: string[];
}

/**
 * Request to create a container
 */
export interface CreateContainerRequest {
  username: string;
  resources?: {
    cpu?: string;
    memory?: string;
    disk?: string;
  };
  sshKeys?: string[];
  labels?: Record<string, string>;
  image?: string;
  enableDocker?: boolean;
  staticIp?: string; // Static IP address (e.g., "10.100.0.100") - empty for DHCP
}

/**
 * Response from creating a container
 */
export interface CreateContainerResponse {
  container: Container;
  message: string;
  sshCommand: string;
}

/**
 * Response from listing containers
 */
export interface ListContainersResponse {
  containers: Container[];
  totalCount: number;
}

/**
 * System info from Containarium API
 */
export interface SystemInfo {
  version: string;
  incusVersion: string;
  hostname: string;
  os: string;
  kernel: string;
  containerCount: number;
  runningCount: number;
  networkCidr: string; // Container network CIDR (e.g., "10.100.0.0/24")
  // System resource info
  totalCpus: number;
  totalMemoryBytes: number;
  availableMemoryBytes: number;
  totalDiskBytes: number;
  availableDiskBytes: number;
}

/**
 * Container runtime metrics (raw from API)
 */
export interface ContainerMetrics {
  name: string;
  cpuUsageSeconds: number;
  memoryUsageBytes: number;
  memoryPeakBytes: number;
  diskUsageBytes: number;
  networkRxBytes: number;
  networkTxBytes: number;
  processCount: number;
}

/**
 * Container metrics with calculated values (CPU percentage)
 */
export interface ContainerMetricsWithRate extends ContainerMetrics {
  cpuUsagePercent: number; // CPU utilization rate (0-100 per core, can exceed 100 with multiple cores)
}

/**
 * Response from metrics endpoint
 */
export interface MetricsResponse {
  metrics: ContainerMetrics[];
}
