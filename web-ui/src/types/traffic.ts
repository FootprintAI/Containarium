/**
 * Network protocol types
 */
export type Protocol = 'UNSPECIFIED' | 'TCP' | 'UDP' | 'ICMP';

/**
 * Connection state (primarily for TCP)
 */
export type ConnectionState =
  | 'UNSPECIFIED'
  | 'NEW'
  | 'ESTABLISHED'
  | 'RELATED'
  | 'TIME_WAIT'
  | 'CLOSE_WAIT'
  | 'FIN_WAIT'
  | 'CLOSED'
  | 'SYN_SENT'
  | 'SYN_RECV';

/**
 * Traffic direction relative to the container
 */
export type TrafficDirection = 'UNSPECIFIED' | 'INGRESS' | 'EGRESS';

/**
 * Traffic event type for real-time updates
 */
export type TrafficEventType = 'UNSPECIFIED' | 'NEW' | 'UPDATE' | 'DESTROY';

/**
 * Active network connection
 */
export interface Connection {
  id: string;
  containerName: string;
  containerIp: string;
  protocol: Protocol;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  state: ConnectionState;
  direction: TrafficDirection;
  bytesSent: number;
  bytesReceived: number;
  packetsSent: number;
  packetsReceived: number;
  firstSeen: string; // ISO timestamp
  lastSeen: string; // ISO timestamp
  timeoutSeconds: number;
}

/**
 * Real-time traffic event
 */
export interface TrafficEvent {
  type: TrafficEventType;
  connection: Connection;
  timestamp: string; // ISO timestamp
}

/**
 * Connection summary for a container
 */
export interface ConnectionSummary {
  containerName: string;
  activeConnections: number;
  tcpConnections: number;
  udpConnections: number;
  totalBytesSent: number;
  totalBytesReceived: number;
  topDestinations: DestinationStats[];
}

/**
 * Statistics for a destination IP
 */
export interface DestinationStats {
  destIp: string;
  connectionCount: number;
  bytesTotal: number;
}

/**
 * Historical connection record
 */
export interface HistoricalConnection {
  id: number;
  containerName: string;
  protocol: Protocol;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  direction: TrafficDirection;
  bytesSent: number;
  bytesReceived: number;
  startedAt: string; // ISO timestamp
  endedAt?: string; // ISO timestamp (null if still active)
  durationSeconds: number;
}

/**
 * Traffic aggregate for time-series data
 */
export interface TrafficAggregate {
  timestamp: string; // ISO timestamp
  destIp?: string;
  destPort?: number;
  bytesSent: number;
  bytesReceived: number;
  connectionCount: number;
}

/**
 * Request to get active connections
 */
export interface GetConnectionsRequest {
  containerName: string;
  protocol?: Protocol;
  destIpPrefix?: string;
  destPort?: number;
  limit?: number;
}

/**
 * Response from getting active connections
 */
export interface GetConnectionsResponse {
  connections: Connection[];
  totalCount: number;
}

/**
 * Response from getting connection summary
 */
export interface GetConnectionSummaryResponse {
  summary: ConnectionSummary;
}

/**
 * Request to query traffic history
 */
export interface QueryTrafficHistoryRequest {
  containerName: string;
  startTime: string; // ISO timestamp
  endTime: string; // ISO timestamp
  destIp?: string;
  destPort?: number;
  offset?: number;
  limit?: number;
}

/**
 * Response from querying traffic history
 */
export interface QueryTrafficHistoryResponse {
  connections: HistoricalConnection[];
  totalCount: number;
}

/**
 * Request to get traffic aggregates
 */
export interface GetTrafficAggregatesRequest {
  containerName: string;
  startTime: string; // ISO timestamp
  endTime: string; // ISO timestamp
  interval?: string; // e.g., "1m", "5m", "1h", "1d"
  groupByDestIp?: boolean;
  groupByDestPort?: boolean;
}

/**
 * Response from getting traffic aggregates
 */
export interface GetTrafficAggregatesResponse {
  aggregates: TrafficAggregate[];
}

/**
 * Format bytes to human-readable string
 */
export function formatBytes(bytes: number | string | undefined | null): string {
  // Handle undefined, null, or string values
  if (bytes === undefined || bytes === null) return '0 B';
  const numBytes = typeof bytes === 'string' ? parseInt(bytes, 10) : bytes;
  if (isNaN(numBytes) || numBytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(numBytes) / Math.log(k));
  return parseFloat((numBytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/**
 * Format duration in seconds to human-readable string
 */
export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
  }
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
}

/**
 * Get a short protocol label
 */
export function getProtocolLabel(protocol: Protocol): string {
  switch (protocol) {
    case 'TCP':
      return 'TCP';
    case 'UDP':
      return 'UDP';
    case 'ICMP':
      return 'ICMP';
    default:
      return '?';
  }
}

/**
 * Get a short connection state label
 */
export function getStateLabel(state: ConnectionState): string {
  switch (state) {
    case 'ESTABLISHED':
      return 'ESTAB';
    case 'SYN_SENT':
      return 'SYN_S';
    case 'SYN_RECV':
      return 'SYN_R';
    case 'TIME_WAIT':
      return 'TIME_W';
    case 'CLOSE_WAIT':
      return 'CLOSE_W';
    case 'FIN_WAIT':
      return 'FIN_W';
    case 'CLOSED':
      return 'CLOSED';
    case 'NEW':
      return 'NEW';
    default:
      return '-';
  }
}
