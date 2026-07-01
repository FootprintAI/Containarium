import { ContaineriumClient } from '@/src/lib/api/client';
import { Server } from '@/src/types/server';
import {
  AlertRulesResponse, AlertingInfoResponse, WebhookDeliveriesResponse,
} from '@/src/types/alerts';
import {
  ClamavSummaryResponse, ClamavReportsResponse, ScanStatusResponse,
  PentestFindingsResponse, PentestFindingSummaryResponse, PentestScanRunsResponse, PentestConfigResponse,
  RemediatePentestFindingResponse,
  ZapAlertsResponse, ZapAlertSummaryResponse, ZapScanRunsResponse, ZapConfigResponse,
} from '@/src/types/security';
import { AuditLogsResponse, AuditLogsParams } from '@/src/types/audit';
import { ConnectionSummary } from '@/src/types/traffic';

export const DEMO_SERVER: Server = {
  id: 'demo',
  name: 'Demo Server',
  endpoint: '__demo__',
  token: 'demo',
  addedAt: 0,
};

function delay<T>(data: T, ms = 300): Promise<T> {
  return new Promise(resolve => setTimeout(() => resolve(data), ms));
}

// ── Alert Rules ───────────────────────────────────────────────────────────────

const DEMO_ALERT_RULES: AlertRulesResponse = {
  rules: [
    {
      id: 'rule-1', name: 'High CPU Usage', expr: 'cpu_usage_percent > 85',
      duration: '5m', severity: 'warning',
      description: 'Container CPU usage has exceeded 85% for 5 minutes.',
      labels: { team: 'platform' }, annotations: { summary: 'CPU high on {{ $labels.container }}' },
      enabled: true, createdAt: '1746220800', updatedAt: '1746220800',
    },
    {
      id: 'rule-2', name: 'Memory Pressure', expr: 'memory_usage_percent > 90',
      duration: '2m', severity: 'critical',
      description: 'Container memory usage is critically high.',
      labels: { team: 'platform' }, annotations: { summary: 'Memory critical on {{ $labels.container }}' },
      enabled: true, createdAt: '1746134400', updatedAt: '1746307200',
    },
    {
      id: 'rule-3', name: 'Container Down', expr: 'container_up == 0',
      duration: '1m', severity: 'critical',
      description: 'A container has been down for more than 1 minute.',
      labels: { team: 'ops' }, annotations: {},
      enabled: true, createdAt: '1746048000', updatedAt: '1746048000',
    },
    {
      id: 'rule-4', name: 'Disk Usage High', expr: 'disk_usage_percent > 80',
      duration: '10m', severity: 'warning',
      description: 'Container disk usage is above 80%.',
      labels: {}, annotations: {},
      enabled: false, createdAt: '1745961600', updatedAt: '1746220800',
    },
  ],
};

const DEMO_DEFAULT_RULES: AlertRulesResponse = {
  rules: [
    {
      id: 'default-1', name: 'High CPU', expr: 'cpu_usage_percent > 90',
      duration: '5m', severity: 'warning', description: 'Default CPU alert rule.',
      labels: { source: 'default' }, annotations: {},
      enabled: true, createdAt: '1740000000', updatedAt: '1740000000',
    },
    {
      id: 'default-2', name: 'High Memory', expr: 'memory_usage_percent > 95',
      duration: '2m', severity: 'critical', description: 'Default memory alert rule.',
      labels: { source: 'default' }, annotations: {},
      enabled: true, createdAt: '1740000000', updatedAt: '1740000000',
    },
  ],
};

const DEMO_ALERTING_INFO: AlertingInfoResponse = {
  enabled: true,
  vmalertStatus: 'healthy',
  alertmanagerStatus: 'healthy',
  webhookUrl: 'https://hooks.slack.com/services/T00DEMO/B00DEMO/xxxdemo',
  totalRules: 6,
  customRules: 4,
  webhookSecretConfigured: true,
};

const DEMO_WEBHOOK_DELIVERIES: WebhookDeliveriesResponse = {
  deliveries: [
    {
      id: 1, timestamp: new Date(Date.now() - 3600000).toISOString(),
      alertName: 'High CPU Usage', source: 'vmalert',
      webhookUrl: 'https://hooks.slack.com/services/T00DEMO/B00DEMO/xxxdemo',
      success: true, httpStatus: 200, errorMessage: '', payloadSize: 512, durationMs: 145,
    },
    {
      id: 2, timestamp: new Date(Date.now() - 7200000).toISOString(),
      alertName: 'Container Down', source: 'vmalert',
      webhookUrl: 'https://hooks.slack.com/services/T00DEMO/B00DEMO/xxxdemo',
      success: true, httpStatus: 200, errorMessage: '', payloadSize: 480, durationMs: 98,
    },
    {
      id: 3, timestamp: new Date(Date.now() - 86400000).toISOString(),
      alertName: 'Memory Pressure', source: 'vmalert',
      webhookUrl: 'https://hooks.slack.com/services/T00DEMO/B00DEMO/xxxdemo',
      success: false, httpStatus: 503, errorMessage: 'Connection timeout', payloadSize: 560, durationMs: 5001,
    },
  ],
  totalCount: 3,
};

// ── Security / ClamAV ─────────────────────────────────────────────────────────

const DEMO_CLAMAV_SUMMARY: ClamavSummaryResponse = {
  containers: [
    {
      containerName: 'alice-container', username: 'alice',
      lastScanAt: new Date(Date.now() - 3600000).toISOString(),
      lastStatus: 'clean', lastFindingsCount: 0, totalScans: 8, infectedScans: 0,
    },
    {
      containerName: 'bob-container', username: 'bob',
      lastScanAt: new Date(Date.now() - 7200000).toISOString(),
      lastStatus: 'infected', lastFindingsCount: 2, totalScans: 5, infectedScans: 1,
    },
    {
      containerName: 'charlie-container', username: 'charlie',
      lastScanAt: '', lastStatus: 'never', lastFindingsCount: 0, totalScans: 0, infectedScans: 0,
    },
    {
      containerName: 'dave-container', username: 'dave',
      lastScanAt: new Date(Date.now() - 86400000).toISOString(),
      lastStatus: 'clean', lastFindingsCount: 0, totalScans: 3, infectedScans: 0,
    },
  ],
  totalContainers: 4, cleanContainers: 2, infectedContainers: 1, neverScannedContainers: 1,
  lastCollectionAt: new Date().toISOString(),
};

const DEMO_CLAMAV_REPORTS: ClamavReportsResponse = {
  reports: [
    {
      id: 1, containerName: 'bob-container', username: 'bob',
      status: 'infected', findingsCount: 2,
      findings: 'Win.Malware.Agent-12345 FOUND in /home/bob/.cache/tmp/payload.exe\nTrojan.GenericKD.5678 FOUND in /tmp/.hidden/run.sh',
      scannedAt: new Date(Date.now() - 7200000).toISOString(),
      scanDuration: '00:02:15', createdAt: new Date(Date.now() - 7200000).toISOString(),
    },
    {
      id: 2, containerName: 'bob-container', username: 'bob',
      status: 'clean', findingsCount: 0, findings: '',
      scannedAt: new Date(Date.now() - 7 * 86400000).toISOString(),
      scanDuration: '00:01:48', createdAt: new Date(Date.now() - 7 * 86400000).toISOString(),
    },
  ],
  totalCount: 2,
};

const DEMO_SCAN_STATUS: ScanStatusResponse = {
  jobs: [],
  pendingCount: 0, runningCount: 0, completedCount: 8, failedCount: 0,
};

// ── Pentest ───────────────────────────────────────────────────────────────────

const DEMO_PENTEST_SUMMARY: PentestFindingSummaryResponse = {
  summary: {
    totalFindings: 7, openFindings: 5, resolvedFindings: 1, suppressedFindings: 1,
    criticalCount: 1, highCount: 2, mediumCount: 2, lowCount: 1, infoCount: 1,
    byCategory: { injection: 2, xss: 1, auth: 1, config: 2, info: 1 },
  },
};

const DEMO_PENTEST_FINDINGS: PentestFindingsResponse = {
  findings: [
    {
      id: 1, fingerprint: 'fp-sqli-001', category: 'injection', severity: 'critical',
      title: 'SQL Injection in Login Endpoint',
      description: 'The login endpoint at /api/auth/login is vulnerable to SQL injection via the username parameter. An attacker can bypass authentication or extract the entire user database.',
      target: 'https://alice.containarium.app/api/auth/login',
      evidence: `POST /api/auth/login\nContent-Type: application/json\n\n{"username":"admin'--","password":"x"}\n\nHTTP/1.1 200 OK (auth bypassed)`,
      cveIds: 'CVE-2024-12345',
      remediation: 'Use parameterised queries or prepared statements. Never interpolate user input into SQL strings.',
      status: 'open', firstScanRunId: 'run-001', lastScanRunId: 'run-003',
      firstSeenAt: new Date(Date.now() - 14 * 86400000).toISOString(),
      lastSeenAt: new Date(Date.now() - 3600000).toISOString(),
      resolvedAt: '', suppressed: false, suppressedReason: '', targetType: 'domain',
    },
    {
      id: 2, fingerprint: 'fp-xss-001', category: 'xss', severity: 'high',
      title: 'Reflected XSS in Search Parameter',
      description: 'The search endpoint reflects user input without sanitisation, allowing script injection.',
      target: 'https://alice.containarium.app/search?q=<script>alert(1)</script>',
      evidence: '<div class="results">Results for: <script>alert(1)</script></div>',
      cveIds: '', remediation: 'Encode all user-supplied values before reflecting them in HTML. Use a Content-Security-Policy header.',
      status: 'open', firstScanRunId: 'run-001', lastScanRunId: 'run-003',
      firstSeenAt: new Date(Date.now() - 14 * 86400000).toISOString(),
      lastSeenAt: new Date(Date.now() - 3600000).toISOString(),
      resolvedAt: '', suppressed: false, suppressedReason: '', targetType: 'domain',
    },
    {
      id: 3, fingerprint: 'fp-rce-001', category: 'injection', severity: 'high',
      title: 'Command Injection via File Upload',
      description: 'The file upload endpoint passes the filename to a shell command without sanitisation.',
      target: 'https://bob.containarium.app/api/upload',
      evidence: 'filename: "file; cat /etc/passwd #.txt" → response includes /etc/passwd content',
      cveIds: 'CVE-2024-67890', remediation: 'Sanitise filenames before use in shell commands. Use safe file-handling APIs.',
      status: 'open', firstScanRunId: 'run-002', lastScanRunId: 'run-003',
      firstSeenAt: new Date(Date.now() - 7 * 86400000).toISOString(),
      lastSeenAt: new Date(Date.now() - 3600000).toISOString(),
      resolvedAt: '', suppressed: false, suppressedReason: '', targetType: 'container',
    },
    {
      id: 4, fingerprint: 'fp-csrf-001', category: 'auth', severity: 'medium',
      title: 'Missing CSRF Token on State-Changing Endpoints',
      description: 'POST endpoints that modify state do not validate a CSRF token.',
      target: 'https://alice.containarium.app/api/settings',
      evidence: 'POST /api/settings with no CSRF token returns HTTP 200.',
      cveIds: '', remediation: 'Implement CSRF tokens (synchroniser token pattern or double-submit cookie).',
      status: 'open', firstScanRunId: 'run-001', lastScanRunId: 'run-003',
      firstSeenAt: new Date(Date.now() - 14 * 86400000).toISOString(),
      lastSeenAt: new Date(Date.now() - 3600000).toISOString(),
      resolvedAt: '', suppressed: false, suppressedReason: '', targetType: 'domain',
    },
    {
      id: 5, fingerprint: 'fp-tls-001', category: 'config', severity: 'medium',
      title: 'TLS 1.0 / 1.1 Still Accepted',
      description: 'The server accepts deprecated TLS 1.0 and 1.1 connections in addition to TLS 1.2/1.3.',
      target: 'https://bob.containarium.app',
      evidence: 'openssl s_client -connect bob.containarium.app:443 -tls1 → Handshake succeeded',
      cveIds: 'CVE-2011-3389', remediation: 'Disable TLS 1.0 and 1.1 in the server configuration. Require TLS 1.2 or higher.',
      status: 'resolved', firstScanRunId: 'run-001', lastScanRunId: 'run-002',
      firstSeenAt: new Date(Date.now() - 14 * 86400000).toISOString(),
      lastSeenAt: new Date(Date.now() - 7 * 86400000).toISOString(),
      resolvedAt: new Date(Date.now() - 3 * 86400000).toISOString(),
      suppressed: false, suppressedReason: '', targetType: 'container',
    },
    {
      id: 6, fingerprint: 'fp-hdr-001', category: 'config', severity: 'low',
      title: 'Missing Security Headers',
      description: 'Responses are missing several recommended HTTP security headers.',
      target: 'https://alice.containarium.app',
      evidence: 'Missing: X-Content-Type-Options, X-Frame-Options, Referrer-Policy',
      cveIds: '', remediation: 'Add security headers via your reverse proxy or application middleware.',
      status: 'open', firstScanRunId: 'run-001', lastScanRunId: 'run-003',
      firstSeenAt: new Date(Date.now() - 14 * 86400000).toISOString(),
      lastSeenAt: new Date(Date.now() - 3600000).toISOString(),
      resolvedAt: '', suppressed: false, suppressedReason: '', targetType: 'domain',
    },
    {
      id: 7, fingerprint: 'fp-info-001', category: 'info', severity: 'info',
      title: 'Server Version Disclosure',
      description: 'The Server response header reveals the web server software and version.',
      target: 'https://alice.containarium.app',
      evidence: 'Server: nginx/1.24.0',
      cveIds: '', remediation: 'Remove or obfuscate the Server header in your nginx configuration.',
      status: 'suppressed', firstScanRunId: 'run-001', lastScanRunId: 'run-003',
      firstSeenAt: new Date(Date.now() - 14 * 86400000).toISOString(),
      lastSeenAt: new Date(Date.now() - 3600000).toISOString(),
      resolvedAt: '', suppressed: true, suppressedReason: 'Accepted risk — not a business concern.',
      targetType: 'domain',
    },
  ],
  totalCount: 7,
};

const DEMO_PENTEST_SCAN_RUNS: PentestScanRunsResponse = {
  scanRuns: [
    {
      id: 'run-003', trigger: 'manual', status: 'completed',
      modules: 'nuclei,trivy', targetsCount: 4,
      criticalCount: 1, highCount: 2, mediumCount: 2, lowCount: 1, infoCount: 1,
      errorMessage: '',
      startedAt: new Date(Date.now() - 3600000).toISOString(),
      completedAt: new Date(Date.now() - 2400000).toISOString(),
      duration: '20m 03s', completedCount: 4,
    },
    {
      id: 'run-002', trigger: 'scheduled', status: 'completed',
      modules: 'nuclei,trivy', targetsCount: 4,
      criticalCount: 1, highCount: 3, mediumCount: 2, lowCount: 1, infoCount: 1,
      errorMessage: '',
      startedAt: new Date(Date.now() - 7 * 86400000).toISOString(),
      completedAt: new Date(Date.now() - 7 * 86400000 + 1200000).toISOString(),
      duration: '20m 14s', completedCount: 4,
    },
  ],
  totalCount: 2,
};

const DEMO_PENTEST_CONFIG: PentestConfigResponse = {
  config: {
    enabled: true, interval: '24h', modules: 'nuclei,trivy',
    nucleiAvailable: true, trivyAvailable: true,
  },
};

// ── ZAP ───────────────────────────────────────────────────────────────────────

const DEMO_ZAP_SUMMARY: ZapAlertSummaryResponse = {
  summary: {
    totalAlerts: 6, openAlerts: 4, resolvedAlerts: 1, suppressedAlerts: 1,
    highCount: 1, mediumCount: 2, lowCount: 2, infoCount: 1,
  },
};

const DEMO_ZAP_ALERTS: ZapAlertsResponse = {
  alerts: [
    {
      id: 1, fingerprint: 'zap-sqli-001', pluginId: '40018',
      alertName: 'SQL Injection', risk: 'high',
      confidence: 'Medium', description: 'SQL injection may be possible.',
      url: 'https://alice.containarium.app/api/users?id=1',
      method: 'GET', evidence: "id=1' OR '1'='1",
      solution: 'Do not trust client-side input. Use parameterised queries.',
      cweIds: 'CWE-89', references: 'https://owasp.org/www-project-web-security-testing-guide/',
      status: 'open', firstScanRunId: 'zrun-001', lastScanRunId: 'zrun-002',
      firstSeenAt: new Date(Date.now() - 14 * 86400000).toISOString(),
      lastSeenAt: new Date(Date.now() - 3600000).toISOString(),
      resolvedAt: '', suppressed: false, suppressedReason: '',
    },
    {
      id: 2, fingerprint: 'zap-csp-001', pluginId: '10038',
      alertName: 'Content Security Policy (CSP) Header Not Set', risk: 'medium',
      confidence: 'High', description: 'Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks.',
      url: 'https://alice.containarium.app',
      method: 'GET', evidence: '',
      solution: 'Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.',
      cweIds: 'CWE-693', references: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
      status: 'open', firstScanRunId: 'zrun-001', lastScanRunId: 'zrun-002',
      firstSeenAt: new Date(Date.now() - 14 * 86400000).toISOString(),
      lastSeenAt: new Date(Date.now() - 3600000).toISOString(),
      resolvedAt: '', suppressed: false, suppressedReason: '',
    },
    {
      id: 3, fingerprint: 'zap-cors-001', pluginId: '40040',
      alertName: 'CORS Misconfiguration', risk: 'medium',
      confidence: 'High', description: 'The CORS configuration allows arbitrary origins.',
      url: 'https://alice.containarium.app/api',
      method: 'OPTIONS', evidence: 'Access-Control-Allow-Origin: *',
      solution: 'Restrict CORS to specific trusted origins.',
      cweIds: 'CWE-942', references: 'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny',
      status: 'open', firstScanRunId: 'zrun-001', lastScanRunId: 'zrun-002',
      firstSeenAt: new Date(Date.now() - 14 * 86400000).toISOString(),
      lastSeenAt: new Date(Date.now() - 3600000).toISOString(),
      resolvedAt: '', suppressed: false, suppressedReason: '',
    },
    {
      id: 4, fingerprint: 'zap-cookie-001', pluginId: '10011',
      alertName: 'Cookie Without Secure Flag', risk: 'low',
      confidence: 'Medium', description: 'A cookie has been set without the secure flag.',
      url: 'https://alice.containarium.app/login',
      method: 'POST', evidence: 'Set-Cookie: session=abc123; Path=/',
      solution: 'Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted channel.',
      cweIds: 'CWE-614', references: '',
      status: 'resolved', firstScanRunId: 'zrun-001', lastScanRunId: 'zrun-001',
      firstSeenAt: new Date(Date.now() - 14 * 86400000).toISOString(),
      lastSeenAt: new Date(Date.now() - 7 * 86400000).toISOString(),
      resolvedAt: new Date(Date.now() - 5 * 86400000).toISOString(),
      suppressed: false, suppressedReason: '',
    },
  ],
  totalCount: 4,
};

const DEMO_ZAP_SCAN_RUNS: ZapScanRunsResponse = {
  scanRuns: [
    {
      id: 'zrun-002', trigger: 'manual', status: 'completed',
      targetsCount: 2, highCount: 1, mediumCount: 2, lowCount: 1, infoCount: 1,
      errorMessage: '',
      startedAt: new Date(Date.now() - 3600000).toISOString(),
      completedAt: new Date(Date.now() - 2700000).toISOString(),
      duration: '15m 22s', completedCount: 2,
    },
    {
      id: 'zrun-001', trigger: 'scheduled', status: 'completed',
      targetsCount: 2, highCount: 2, mediumCount: 3, lowCount: 2, infoCount: 1,
      errorMessage: '',
      startedAt: new Date(Date.now() - 7 * 86400000).toISOString(),
      completedAt: new Date(Date.now() - 7 * 86400000 + 900000).toISOString(),
      duration: '15m 00s', completedCount: 2,
    },
  ],
  totalCount: 2,
};

const DEMO_ZAP_CONFIG: ZapConfigResponse = {
  config: {
    enabled: true, interval: '24h', zapAvailable: true, zapVersion: '2.15.0',
  },
};

// ── Audit ─────────────────────────────────────────────────────────────────────

const DEMO_AUDIT_LOGS: AuditLogsResponse = {
  logs: [
    { id: 1, timestamp: new Date(Date.now() - 600000).toISOString(), username: 'alice', action: 'ssh_login', resourceType: 'container', resourceId: 'alice-container', detail: 'SSH login from 203.0.113.42', sourceIp: '203.0.113.42', statusCode: 200 },
    { id: 2, timestamp: new Date(Date.now() - 1200000).toISOString(), username: 'bob', action: 'api_post', resourceType: 'container', resourceId: 'bob-container', detail: 'Create container', sourceIp: '198.51.100.10', statusCode: 201 },
    { id: 3, timestamp: new Date(Date.now() - 1800000).toISOString(), username: 'alice', action: 'EVENT_TYPE_CONTAINER_STARTED', resourceType: 'container', resourceId: 'alice-container', detail: 'Container started', sourceIp: '', statusCode: 200 },
    { id: 4, timestamp: new Date(Date.now() - 3600000).toISOString(), username: 'charlie', action: 'api_delete', resourceType: 'container', resourceId: 'temp-container', detail: 'Delete container', sourceIp: '10.0.0.5', statusCode: 200 },
    { id: 5, timestamp: new Date(Date.now() - 7200000).toISOString(), username: 'admin', action: 'api_put', resourceType: 'route', resourceId: 'alice.containarium.app', detail: 'Update proxy route', sourceIp: '10.0.0.1', statusCode: 200 },
    { id: 6, timestamp: new Date(Date.now() - 10800000).toISOString(), username: 'dave', action: 'ssh_login', resourceType: 'container', resourceId: 'dave-container', detail: 'SSH login from 192.0.2.100', sourceIp: '192.0.2.100', statusCode: 200 },
    { id: 7, timestamp: new Date(Date.now() - 14400000).toISOString(), username: 'bob', action: 'terminal_access', resourceType: 'container', resourceId: 'bob-container', detail: 'Terminal session opened', sourceIp: '198.51.100.10', statusCode: 200 },
    { id: 8, timestamp: new Date(Date.now() - 86400000).toISOString(), username: 'alice', action: 'EVENT_TYPE_APP_DEPLOYED', resourceType: 'app', resourceId: 'alice-app', detail: 'App deployed successfully', sourceIp: '', statusCode: 200 },
  ],
  totalCount: 8,
};

// ── Traffic ───────────────────────────────────────────────────────────────────

const DEMO_CONNECTION_SUMMARY: ConnectionSummary = {
  containerName: 'alice-container',
  activeConnections: 12,
  tcpConnections: 10,
  udpConnections: 2,
  totalBytesSent: 1024 * 1024 * 45,
  totalBytesReceived: 1024 * 1024 * 120,
  topDestinations: [
    { destIp: '8.8.8.8', connectionCount: 3, bytesTotal: 1024 * 1024 * 10 },
    { destIp: '142.250.80.14', connectionCount: 5, bytesTotal: 1024 * 1024 * 80 },
    { destIp: '151.101.65.140', connectionCount: 2, bytesTotal: 1024 * 1024 * 30 },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────

export class DemoClient extends ContaineriumClient {
  constructor() {
    super(DEMO_SERVER);
  }

  // Alert hooks
  async listAlertRules(): Promise<AlertRulesResponse> { return delay(DEMO_ALERT_RULES); }
  async getAlertingInfo(): Promise<AlertingInfoResponse> { return delay(DEMO_ALERTING_INFO); }
  async listDefaultAlertRules(): Promise<AlertRulesResponse> { return delay(DEMO_DEFAULT_RULES); }
  async listWebhookDeliveries(): Promise<WebhookDeliveriesResponse> { return delay(DEMO_WEBHOOK_DELIVERIES); }

  // ClamAV hooks
  async getClamavSummary(): Promise<ClamavSummaryResponse> { return delay(DEMO_CLAMAV_SUMMARY); }
  async listClamavReports(): Promise<ClamavReportsResponse> { return delay(DEMO_CLAMAV_REPORTS); }
  async getScanStatus(): Promise<ScanStatusResponse> { return delay(DEMO_SCAN_STATUS); }
  async triggerClamavScan(): Promise<{ message: string; scannedCount: number }> {
    return delay({ message: 'Scan queued (demo mode)', scannedCount: 0 });
  }

  // Pentest
  async getPentestFindingSummary(): Promise<PentestFindingSummaryResponse> { return delay(DEMO_PENTEST_SUMMARY); }
  async listPentestFindings(_params?: import('@/src/types/security').ListPentestFindingsParams): Promise<PentestFindingsResponse> { return delay(DEMO_PENTEST_FINDINGS); }
  async listPentestScanRuns(_containerName?: string, _limit?: number, _offset?: number): Promise<PentestScanRunsResponse> { return delay(DEMO_PENTEST_SCAN_RUNS); }
  async getPentestConfig(): Promise<PentestConfigResponse> { return delay(DEMO_PENTEST_CONFIG); }
  async triggerPentestScan(_containerName?: string): Promise<{ scanRunId: string; message: string }> {
    return delay({ scanRunId: 'demo-run', message: 'Scan triggered (demo mode)' });
  }
  async remediatePentestFinding(_findingId: number): Promise<RemediatePentestFindingResponse> {
    return delay({ success: true, message: 'Upgraded libssl from 1.1.1f to 1.1.1n', packageName: 'libssl', oldVersion: '1.1.1f', newVersion: '1.1.1n' });
  }

  // ZAP
  async getZapAlertSummary(): Promise<ZapAlertSummaryResponse> { return delay(DEMO_ZAP_SUMMARY); }
  async listZapAlerts(): Promise<ZapAlertsResponse> { return delay(DEMO_ZAP_ALERTS); }
  async listZapScanRuns(): Promise<ZapScanRunsResponse> { return delay(DEMO_ZAP_SCAN_RUNS); }
  async getZapConfig(): Promise<ZapConfigResponse> { return delay(DEMO_ZAP_CONFIG); }
  async triggerZapScan(): Promise<{ scanRunId: string; message: string }> {
    return delay({ scanRunId: 'demo-zrun', message: 'ZAP scan triggered (demo mode)' });
  }

  // Monitoring
  async getMonitoringInfo(): Promise<{ enabled: boolean; grafanaUrl: string; victoriaMetricsUrl: string }> {
    return delay({ enabled: true, grafanaUrl: 'https://grafana.containarium.app/d/demo', victoriaMetricsUrl: '' });
  }

  // Audit
  async getAuditLogs(_params?: AuditLogsParams): Promise<AuditLogsResponse> { return delay(DEMO_AUDIT_LOGS); }

  // Traffic
  async getConnections(): Promise<{ connections: []; totalCount: number }> {
    return delay({ connections: [] as [], totalCount: 0 });
  }
  async getConnectionSummary(): Promise<ConnectionSummary> { return delay(DEMO_CONNECTION_SUMMARY); }
  async getTrafficHistory(): Promise<{ connections: []; totalCount: number }> {
    return delay({ connections: [] as [], totalCount: 0 });
  }
  async getTrafficAggregates(): Promise<[]> { return delay([] as []); }

  // Alert write ops (no-op in demo)
  async createAlertRule(): Promise<(typeof DEMO_ALERT_RULES.rules)[0]> {
    return delay(DEMO_ALERT_RULES.rules[0]);
  }
  async updateAlertRule(): Promise<(typeof DEMO_ALERT_RULES.rules)[0]> {
    return delay(DEMO_ALERT_RULES.rules[0]);
  }
  async deleteAlertRule(): Promise<void> { return delay(undefined as unknown as void); }
  async updateAlertingConfig(): Promise<{ webhookUrl: string; success: boolean }> {
    return delay({ webhookUrl: DEMO_ALERTING_INFO.webhookUrl, success: true });
  }
  async testWebhook(): Promise<{ success: boolean; statusCode: number; message: string }> {
    return delay({ success: true, statusCode: 200, message: 'Webhook test sent (demo mode)' });
  }
  async suppressPentestFinding(): Promise<{ message: string }> {
    return delay({ message: 'Suppressed (demo mode)' });
  }
  async suppressZapAlert(): Promise<{ message: string }> {
    return delay({ message: 'Suppressed (demo mode)' });
  }
}
