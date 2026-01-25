/**
 * App state enum
 */
export type AppState =
  | 'APP_STATE_UNSPECIFIED'
  | 'APP_STATE_UPLOADING'
  | 'APP_STATE_BUILDING'
  | 'APP_STATE_RUNNING'
  | 'APP_STATE_STOPPED'
  | 'APP_STATE_FAILED'
  | 'APP_STATE_RESTARTING';

/**
 * ACL preset enum
 */
export type ACLPreset =
  | 'ACL_PRESET_UNSPECIFIED'
  | 'ACL_PRESET_FULL_ISOLATION'
  | 'ACL_PRESET_HTTP_ONLY'
  | 'ACL_PRESET_PERMISSIVE'
  | 'ACL_PRESET_CUSTOM';

/**
 * ACL action enum
 */
export type ACLAction =
  | 'ACL_ACTION_UNSPECIFIED'
  | 'ACL_ACTION_ALLOW'
  | 'ACL_ACTION_DROP'
  | 'ACL_ACTION_REJECT';

/**
 * App resources
 */
export interface AppResources {
  cpu: string;
  memory: string;
  disk: string;
}

/**
 * Proxy route configuration
 */
export interface ProxyRoute {
  subdomain: string;
  fullDomain: string;
  containerIp: string;
  port: number;
  active: boolean;
  appId?: string;
  appName?: string;
  username?: string;
}

/**
 * ACL rule
 */
export interface ACLRule {
  priority?: number;
  action: ACLAction;
  source: string;
  destination: string;
  destinationPort: string;
  protocol: string;
  description: string;
}

/**
 * Network ACL
 */
export interface NetworkACL {
  id?: string;
  name: string;
  description: string;
  preset: ACLPreset;
  ingressRules: ACLRule[];
  egressRules: ACLRule[];
  appId?: string;
  containerName?: string;
}

/**
 * App information from Containarium API
 */
export interface App {
  id: string;
  name: string;
  username: string;
  containerName: string;
  subdomain: string;
  fullDomain: string;
  port: number;
  state: AppState;
  dockerImage?: string;
  dockerfilePath?: string;
  envVars: Record<string, string>;
  createdAt: string;
  updatedAt: string;
  deployedAt?: string;
  errorMessage?: string;
  restartCount: number;
  containerIp?: string;
  aclPreset?: ACLPreset;
  route?: ProxyRoute;
  resources?: AppResources;
}

/**
 * Response from listing apps
 */
export interface ListAppsResponse {
  apps: App[];
  totalCount: number;
}

/**
 * Response from getting an app
 */
export interface GetAppResponse {
  app: App;
}

/**
 * Network node for topology visualization
 */
export interface NetworkNode {
  id: string;
  type: 'proxy' | 'container' | 'app';
  name: string;
  ipAddress?: string;
  state: string;
  aclName?: string;
}

/**
 * Network edge for topology visualization
 */
export interface NetworkEdge {
  source: string;
  target: string;
  type: 'route' | 'blocked' | 'allowed';
  ports?: string;
  protocol?: string;
}

/**
 * Network topology
 */
export interface NetworkTopology {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
  networkCidr: string;
  gatewayIp: string;
}

/**
 * Response from getting routes
 */
export interface GetRoutesResponse {
  routes: ProxyRoute[];
  totalCount: number;
}

/**
 * Response from getting ACL
 */
export interface GetACLResponse {
  acl: NetworkACL;
}

/**
 * Response from getting network topology
 */
export interface GetNetworkTopologyResponse {
  topology: NetworkTopology;
}

/**
 * ACL preset info
 */
export interface ACLPresetInfo {
  preset: ACLPreset;
  name: string;
  description: string;
  defaultIngressRules: ACLRule[];
  defaultEgressRules: ACLRule[];
}

/**
 * Response from listing ACL presets
 */
export interface ListACLPresetsResponse {
  presets: ACLPresetInfo[];
}

/**
 * Helper function to get friendly state name
 */
export function getAppStateName(state: AppState): string {
  switch (state) {
    case 'APP_STATE_UPLOADING':
      return 'Uploading';
    case 'APP_STATE_BUILDING':
      return 'Building';
    case 'APP_STATE_RUNNING':
      return 'Running';
    case 'APP_STATE_STOPPED':
      return 'Stopped';
    case 'APP_STATE_FAILED':
      return 'Failed';
    case 'APP_STATE_RESTARTING':
      return 'Restarting';
    default:
      return 'Unknown';
  }
}

/**
 * Helper function to get state color
 */
export function getAppStateColor(state: AppState): 'success' | 'error' | 'warning' | 'info' | 'default' {
  switch (state) {
    case 'APP_STATE_RUNNING':
      return 'success';
    case 'APP_STATE_FAILED':
      return 'error';
    case 'APP_STATE_STOPPED':
      return 'default';
    case 'APP_STATE_UPLOADING':
    case 'APP_STATE_BUILDING':
    case 'APP_STATE_RESTARTING':
      return 'warning';
    default:
      return 'info';
  }
}

/**
 * Helper function to get preset name
 */
export function getACLPresetName(preset: ACLPreset): string {
  switch (preset) {
    case 'ACL_PRESET_FULL_ISOLATION':
      return 'Full Isolation';
    case 'ACL_PRESET_HTTP_ONLY':
      return 'HTTP Only';
    case 'ACL_PRESET_PERMISSIVE':
      return 'Permissive';
    case 'ACL_PRESET_CUSTOM':
      return 'Custom';
    default:
      return 'Not Configured';
  }
}

/**
 * Helper function to get action display
 */
export function getACLActionDisplay(action: ACLAction): { label: string; color: 'success' | 'error' | 'warning' } {
  switch (action) {
    case 'ACL_ACTION_ALLOW':
      return { label: 'Allow', color: 'success' };
    case 'ACL_ACTION_DROP':
      return { label: 'Drop', color: 'error' };
    case 'ACL_ACTION_REJECT':
      return { label: 'Reject', color: 'warning' };
    default:
      return { label: 'Unknown', color: 'warning' };
  }
}
