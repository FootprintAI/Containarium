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
  podmanEnabled: boolean;
  stack: string;
  createdAt: string;
  updatedAt: string;
  labels: Record<string, string>;
  sshKeys: string[];
  backendId?: string;
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
  enablePodman?: boolean;
  stack?: string; // Software stack to install (e.g., "nodejs", "python", "fullstack")
  staticIp?: string; // Static IP address (e.g., "10.100.0.100") - empty for DHCP
  gpu?: string; // GPU device ID for passthrough (e.g., "0" for first GPU)
  backendId?: string; // Target backend for creation (empty = primary)
}

/**
 * Backend instance information
 */
export interface BackendInfo {
  id: string;
  type: 'gcp' | 'tunnel';
  healthy: boolean;
  priority: number;
}

/**
 * Available software stacks for container provisioning
 */
export interface Stack {
  id: string;
  name: string;
  description: string;
  icon: string;
}

/**
 * Pre-defined software stacks (matching configs/stacks.yaml)
 */
export const AVAILABLE_STACKS: Stack[] = [
  { id: '', name: 'None', description: 'No pre-configured stack', icon: 'none' },
  { id: 'nodejs', name: 'Node.js Development', description: 'Node.js LTS with npm, yarn, pnpm, TypeScript', icon: 'nodejs' },
  { id: 'python', name: 'Python Development', description: 'Python 3 with pip, virtualenv, poetry', icon: 'python' },
  { id: 'golang', name: 'Go Development', description: 'Go with gopls, golangci-lint', icon: 'golang' },
  { id: 'rust', name: 'Rust Development', description: 'Rust with cargo', icon: 'rust' },
  { id: 'datascience', name: 'Data Science', description: 'Python with Jupyter, pandas, numpy, scikit-learn', icon: 'jupyter' },
  { id: 'docker', name: 'Docker Development', description: 'Docker CE container runtime', icon: 'docker' },
  { id: 'devops', name: 'DevOps Tools', description: 'kubectl, Terraform, infrastructure tools', icon: 'kubernetes' },
  { id: 'database', name: 'Database Clients', description: 'PostgreSQL, MySQL, Redis CLI clients', icon: 'database' },
  { id: 'fullstack', name: 'Full Stack Web', description: 'Node.js, Python, database clients', icon: 'code' },
];

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
  // CPU load averages
  cpuLoad1min?: number;
  cpuLoad5min?: number;
  cpuLoad15min?: number;
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

/**
 * Collaborator with access to a container
 */
export interface Collaborator {
  id: string;
  containerName: string;
  ownerUsername: string;
  collaboratorUsername: string;
  accountName: string;
  sshPublicKey: string;
  addedAt: number;
  createdBy: string;
  hasSudo: boolean;
  hasContainerRuntime: boolean;
}

/**
 * Request to add a collaborator
 */
export interface AddCollaboratorRequest {
  collaboratorUsername: string;
  sshPublicKey: string;
  grantSudo?: boolean;
  grantContainerRuntime?: boolean;
}

/**
 * Response from listing collaborators
 */
export interface ListCollaboratorsResponse {
  collaborators: Collaborator[];
  totalCount: number;
}
