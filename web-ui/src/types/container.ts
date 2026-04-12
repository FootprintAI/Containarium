/**
 * Container state enum
 */
export type ContainerState = 'Running' | 'Stopped' | 'Frozen' | 'Creating' | 'Provisioning' | 'Error' | 'Unknown';

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
  type: 'local' | 'gcp' | 'tunnel';
  healthy: boolean;
  priority: number;
  version?: string;
  hostname?: string;
  uptimeSeconds?: number;
  lastSeenAt?: string;
  os?: string;
  containerCount?: number;
  gpus?: Array<{ vendor?: string; modelName?: string; vramBytes?: number }>;
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
  { id: 'gpu', name: 'GPU / CUDA Development', description: 'NVIDIA drivers, CUDA toolkit, cuDNN', icon: 'gpu' },
  { id: 'gpu-docker', name: 'GPU + Docker (CUDA)', description: 'NVIDIA CUDA, Docker CE, nvidia-container-toolkit', icon: 'gpu' },
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
  // GPU devices
  gpus?: GPUInfo[];
  // Backend identifier (set for peer backends)
  backendId?: string;
}

/**
 * System info response including peer backends
 */
export interface SystemInfoResponse {
  info: SystemInfo;
  peers?: SystemInfo[];
}

/**
 * GPU device information
 */
export interface GPUInfo {
  vendor: string;   // enum string: GPU_VENDOR_NVIDIA, GPU_VENDOR_AMD, etc.
  model: string;    // enum string: GPU_MODEL_NVIDIA_RTX_4090, etc.
  modelName: string; // raw model name from driver
  pciAddress: string;
  driverVersion: string;
  cudaVersion: string;
  vramBytes: number;
}

/**
 * Get display name for a GPU vendor enum
 */
export function gpuVendorDisplayName(vendor: string): string {
  switch (vendor) {
    case 'GPU_VENDOR_NVIDIA': return 'NVIDIA';
    case 'GPU_VENDOR_AMD': return 'AMD';
    case 'GPU_VENDOR_INTEL': return 'Intel';
    default: return vendor || 'Unknown';
  }
}

/**
 * Get display name for a GPU model enum
 */
export function gpuModelDisplayName(model: string, modelName?: string): string {
  const map: Record<string, string> = {
    'GPU_MODEL_NVIDIA_RTX_5090': 'RTX 5090',
    'GPU_MODEL_NVIDIA_RTX_5080': 'RTX 5080',
    'GPU_MODEL_NVIDIA_RTX_4090': 'RTX 4090',
    'GPU_MODEL_NVIDIA_RTX_4080': 'RTX 4080',
    'GPU_MODEL_NVIDIA_RTX_4070_TI': 'RTX 4070 Ti',
    'GPU_MODEL_NVIDIA_RTX_4070': 'RTX 4070',
    'GPU_MODEL_NVIDIA_RTX_3090': 'RTX 3090',
    'GPU_MODEL_NVIDIA_RTX_3080': 'RTX 3080',
    'GPU_MODEL_NVIDIA_A100': 'A100',
    'GPU_MODEL_NVIDIA_A10': 'A10',
    'GPU_MODEL_NVIDIA_A10G': 'A10G',
    'GPU_MODEL_NVIDIA_H100': 'H100',
    'GPU_MODEL_NVIDIA_H200': 'H200',
    'GPU_MODEL_NVIDIA_L4': 'L4',
    'GPU_MODEL_NVIDIA_L40': 'L40',
    'GPU_MODEL_NVIDIA_L40S': 'L40S',
    'GPU_MODEL_NVIDIA_T4': 'T4',
    'GPU_MODEL_NVIDIA_V100': 'V100',
    'GPU_MODEL_NVIDIA_B200': 'B200',
    'GPU_MODEL_AMD_MI300X': 'MI300X',
    'GPU_MODEL_AMD_MI250X': 'MI250X',
    'GPU_MODEL_AMD_RX_7900_XTX': 'RX 7900 XTX',
    'GPU_MODEL_INTEL_MAX_1550': 'Max 1550',
    'GPU_MODEL_INTEL_ARC_A770': 'Arc A770',
  };
  return map[model] || modelName || model || 'Unknown GPU';
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
