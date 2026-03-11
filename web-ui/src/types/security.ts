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
