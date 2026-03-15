/**
 * ClamAV scan report
 */
export interface ClamavReport {
  id: number;
  containerName: string;
  username: string;
  status: 'clean' | 'infected';
  findingsCount: number;
  findings: string;
  scannedAt: string;
  scanDuration: string;
  createdAt: string;
}

/**
 * ClamAV container summary
 */
export interface ClamavContainerSummary {
  containerName: string;
  username: string;
  lastScanAt: string;
  lastStatus: 'clean' | 'infected' | 'never';
  lastFindingsCount: number;
  totalScans: number;
  infectedScans: number;
}

/**
 * ClamAV summary response
 */
export interface ClamavSummaryResponse {
  containers: ClamavContainerSummary[];
  totalContainers: number;
  cleanContainers: number;
  infectedContainers: number;
  neverScannedContainers: number;
  lastCollectionAt: string;
}

/**
 * ClamAV reports list response
 */
export interface ClamavReportsResponse {
  reports: ClamavReport[];
  totalCount: number;
}

/**
 * Response from triggering a ClamAV scan
 */
export interface TriggerScanResponse {
  message: string;
  scannedCount: number;
}

/**
 * Parameters for listing ClamAV reports
 */
export interface ListClamavReportsParams {
  containerName?: string;
  status?: string;
  from?: string;
  to?: string;
  limit?: number;
  offset?: number;
}

/**
 * A queued ClamAV scan job
 */
export interface ScanJob {
  id: number;
  containerName: string;
  username: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  retryCount: number;
  errorMessage: string;
  createdAt: string;
  startedAt: string;
  completedAt: string;
}

/**
 * Response from GET /v1/security/scan-status
 */
export interface ScanStatusResponse {
  jobs: ScanJob[];
  pendingCount: number;
  runningCount: number;
  completedCount: number;
  failedCount: number;
}

// ============= Pentest Types =============

export interface PentestScanRun {
  id: string;
  trigger: string;
  status: 'running' | 'completed' | 'failed';
  modules: string;
  targetsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  errorMessage: string;
  startedAt: string;
  completedAt: string;
  duration: string;
  completedCount: number;
}

export interface PentestFinding {
  id: number;
  fingerprint: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  target: string;
  evidence: string;
  cveIds: string;
  remediation: string;
  status: 'open' | 'resolved' | 'suppressed';
  firstScanRunId: string;
  lastScanRunId: string;
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string;
  suppressed: boolean;
  suppressedReason: string;
}

export interface PentestFindingSummary {
  totalFindings: number;
  openFindings: number;
  resolvedFindings: number;
  suppressedFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  byCategory: Record<string, number>;
}

export interface PentestConfig {
  enabled: boolean;
  interval: string;
  modules: string;
  nucleiAvailable: boolean;
  trivyAvailable: boolean;
}

export interface PentestScanRunsResponse {
  scanRuns: PentestScanRun[];
  totalCount: number;
}

export interface PentestFindingsResponse {
  findings: PentestFinding[];
  totalCount: number;
}

export interface PentestFindingSummaryResponse {
  summary: PentestFindingSummary;
}

export interface PentestConfigResponse {
  config: PentestConfig;
}

export interface TriggerPentestScanResponse {
  scanRunId: string;
  message: string;
}

export interface InstallPentestToolResponse {
  success: boolean;
  message: string;
}

export interface ListPentestFindingsParams {
  severity?: string;
  category?: string;
  status?: string;
  limit?: number;
  offset?: number;
}
