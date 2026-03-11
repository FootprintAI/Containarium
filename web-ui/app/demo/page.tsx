'use client';

import { useState } from 'react';
import {
  Box,
  Typography,
  Tabs,
  Tab,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
  TextField,
  Stack,
  LinearProgress,
  IconButton,
} from '@mui/material';
import DnsIcon from '@mui/icons-material/Dns';
import AppsIcon from '@mui/icons-material/Apps';
import HubIcon from '@mui/icons-material/Hub';
import TimelineIcon from '@mui/icons-material/Timeline';
import ShieldIcon from '@mui/icons-material/Shield';
import MonitorHeartIcon from '@mui/icons-material/MonitorHeart';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import RefreshIcon from '@mui/icons-material/Refresh';
import DownloadIcon from '@mui/icons-material/Download';
import ScannerIcon from '@mui/icons-material/Scanner';
import HourglassEmptyIcon from '@mui/icons-material/HourglassEmpty';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import AppBar from '@/src/components/layout/AppBar';
import ContainerTopology from '@/src/components/containers/ContainerTopology';
import LabelEditorDialog from '@/src/components/containers/LabelEditorDialog';
import AppsView from '@/src/components/apps/AppsView';
import NetworkTopologyView from '@/src/components/network/NetworkTopologyView';
import TrafficView, { RouteTrafficStats } from '@/src/components/traffic/TrafficView';
import { Container, ContainerMetricsWithRate, SystemInfo } from '@/src/types/container';
import { App, NetworkTopology, ProxyRoute, NetworkNode, PassthroughRoute, DNSRecord } from '@/src/types/app';
import { ClamavContainerSummary, ScanStatusResponse, ScanJob } from '@/src/types/security';

// Mock system info for system resources card
const mockSystemInfo: SystemInfo = {
  version: '0.11.0',
  incusVersion: '6.21',
  hostname: 'gpu-cluster-01',
  os: 'Ubuntu 24.04 LTS',
  kernel: '6.8.0-49-generic',
  containerCount: 6,
  runningCount: 5,
  networkCidr: '10.0.100.0/24',
  totalCpus: 32,
  totalMemoryBytes: 128 * 1024 * 1024 * 1024, // 128GB
  availableMemoryBytes: 48 * 1024 * 1024 * 1024, // 48GB available (80GB used)
  totalDiskBytes: 2 * 1024 * 1024 * 1024 * 1024, // 2TB
  availableDiskBytes: 1.2 * 1024 * 1024 * 1024 * 1024, // 1.2TB available (800GB used)
};

// Mock containers with varied states and resources
const mockContainers: Container[] = [
  {
    name: 'alice-container',
    username: 'alice',
    state: 'Running',
    ipAddress: '10.0.100.12',
    cpu: '8',
    memory: '16GB',
    disk: '100GB',
    gpu: 'NVIDIA RTX 4090',
    image: 'ubuntu:24.04',
    podmanEnabled: true,
    stack: '',
    createdAt: '2025-01-10T08:30:00Z',
    updatedAt: '2025-01-15T10:00:00Z',
    labels: { team: 'ml-research' },
    sshKeys: [],
  },
  {
    name: 'bob-container',
    username: 'bob',
    state: 'Running',
    ipAddress: '10.0.100.15',
    cpu: '4',
    memory: '8GB',
    disk: '50GB',
    gpu: '',
    image: 'ubuntu:22.04',
    podmanEnabled: true,
    stack: '',
    createdAt: '2025-01-12T14:20:00Z',
    updatedAt: '2025-01-15T09:45:00Z',
    labels: { team: 'backend' },
    sshKeys: [],
  },
  {
    name: 'charlie-container',
    username: 'charlie',
    state: 'Running',
    ipAddress: '10.0.100.18',
    cpu: '16',
    memory: '32GB',
    disk: '200GB',
    gpu: 'NVIDIA A100',
    image: 'ubuntu:24.04',
    podmanEnabled: true,
    stack: '',
    createdAt: '2025-01-08T11:00:00Z',
    updatedAt: '2025-01-15T10:15:00Z',
    labels: { team: 'ml-training' },
    sshKeys: [],
  },
  {
    name: 'david-container',
    username: 'david',
    state: 'Stopped',
    ipAddress: '',
    cpu: '2',
    memory: '4GB',
    disk: '30GB',
    gpu: '',
    image: 'ubuntu:22.04',
    podmanEnabled: false,
    stack: '',
    createdAt: '2025-01-05T09:00:00Z',
    updatedAt: '2025-01-14T18:00:00Z',
    labels: { team: 'frontend' },
    sshKeys: [],
  },
  {
    name: 'emma-container',
    username: 'emma',
    state: 'Running',
    ipAddress: '10.0.100.22',
    cpu: '4',
    memory: '8GB',
    disk: '50GB',
    gpu: '',
    image: 'debian:12',
    podmanEnabled: true,
    stack: '',
    createdAt: '2025-01-11T16:30:00Z',
    updatedAt: '2025-01-15T08:20:00Z',
    labels: { team: 'devops' },
    sshKeys: [],
  },
  {
    name: 'frank-container',
    username: 'frank',
    state: 'Creating',
    ipAddress: '',
    cpu: '8',
    memory: '16GB',
    disk: '100GB',
    gpu: 'NVIDIA RTX 3090',
    image: 'ubuntu:24.04',
    podmanEnabled: true,
    stack: '',
    createdAt: '2025-01-15T10:25:00Z',
    updatedAt: '2025-01-15T10:25:00Z',
    labels: { team: 'ml-research' },
    sshKeys: [],
  },
];

// Mock metrics with varied usage levels
const mockMetricsMap: Record<string, ContainerMetricsWithRate> = {
  'alice-container': {
    name: 'alice-container',
    cpuUsageSeconds: 45000,
    cpuUsagePercent: 320, // 320% = using 3.2 of 8 cores (40% bar)
    memoryUsageBytes: 12 * 1024 * 1024 * 1024, // 12GB of 16GB (75%)
    memoryPeakBytes: 14 * 1024 * 1024 * 1024,
    diskUsageBytes: 65 * 1024 * 1024 * 1024, // 65GB of 100GB (65%)
    networkRxBytes: 2.5 * 1024 * 1024 * 1024,
    networkTxBytes: 1.2 * 1024 * 1024 * 1024,
    processCount: 156,
  },
  'bob-container': {
    name: 'bob-container',
    cpuUsageSeconds: 12000,
    cpuUsagePercent: 85, // 85% = low usage of 4 cores (21% bar)
    memoryUsageBytes: 3.2 * 1024 * 1024 * 1024, // 3.2GB of 8GB (40%)
    memoryPeakBytes: 5 * 1024 * 1024 * 1024,
    diskUsageBytes: 22 * 1024 * 1024 * 1024, // 22GB of 50GB (44%)
    networkRxBytes: 850 * 1024 * 1024,
    networkTxBytes: 320 * 1024 * 1024,
    processCount: 42,
  },
  'charlie-container': {
    name: 'charlie-container',
    cpuUsageSeconds: 180000,
    cpuUsagePercent: 1450, // 1450% = using 14.5 of 16 cores (90% bar - high!)
    memoryUsageBytes: 28 * 1024 * 1024 * 1024, // 28GB of 32GB (87.5% - high!)
    memoryPeakBytes: 30 * 1024 * 1024 * 1024,
    diskUsageBytes: 145 * 1024 * 1024 * 1024, // 145GB of 200GB (72.5%)
    networkRxBytes: 15 * 1024 * 1024 * 1024,
    networkTxBytes: 8 * 1024 * 1024 * 1024,
    processCount: 312,
  },
  'emma-container': {
    name: 'emma-container',
    cpuUsageSeconds: 8500,
    cpuUsagePercent: 45, // 45% = very low (11% bar)
    memoryUsageBytes: 1.8 * 1024 * 1024 * 1024, // 1.8GB of 8GB (22.5%)
    memoryPeakBytes: 3 * 1024 * 1024 * 1024,
    diskUsageBytes: 8 * 1024 * 1024 * 1024, // 8GB of 50GB (16%)
    networkRxBytes: 120 * 1024 * 1024,
    networkTxBytes: 45 * 1024 * 1024,
    processCount: 28,
  },
};

// Mock deployed apps
const mockApps: App[] = [
  {
    id: 'app-001',
    name: 'ml-dashboard',
    username: 'alice',
    containerName: 'alice-container',
    subdomain: 'alice-ml-dashboard',
    fullDomain: 'alice-ml-dashboard.containarium.dev',
    port: 8080,
    state: 'APP_STATE_RUNNING',
    dockerImage: 'ml-dashboard:v2.1.0',
    envVars: { NODE_ENV: 'production', API_URL: '/api' },
    createdAt: '2025-01-12T10:00:00Z',
    updatedAt: '2025-01-15T08:30:00Z',
    deployedAt: '2025-01-15T08:30:00Z',
    restartCount: 0,
    containerIp: '10.0.100.12',
    aclPreset: 'ACL_PRESET_HTTP_ONLY',
    resources: { cpu: '2', memory: '4GB', disk: '10GB' },
  },
  {
    id: 'app-002',
    name: 'api-server',
    username: 'bob',
    containerName: 'bob-container',
    subdomain: 'bob-api-server',
    fullDomain: 'bob-api-server.containarium.dev',
    port: 3000,
    state: 'APP_STATE_RUNNING',
    dockerImage: 'api-server:latest',
    envVars: { NODE_ENV: 'production', DB_HOST: 'localhost' },
    createdAt: '2025-01-10T14:00:00Z',
    updatedAt: '2025-01-14T16:20:00Z',
    deployedAt: '2025-01-14T16:20:00Z',
    restartCount: 2,
    containerIp: '10.0.100.15',
    aclPreset: 'ACL_PRESET_PERMISSIVE',
    resources: { cpu: '1', memory: '2GB', disk: '5GB' },
  },
  {
    id: 'app-003',
    name: 'training-monitor',
    username: 'charlie',
    containerName: 'charlie-container',
    subdomain: 'charlie-training-monitor',
    fullDomain: 'charlie-training-monitor.containarium.dev',
    port: 5000,
    state: 'APP_STATE_RUNNING',
    dockerImage: 'training-monitor:v1.5.2',
    envVars: { FLASK_ENV: 'production', GPU_ENABLED: 'true' },
    createdAt: '2025-01-08T11:30:00Z',
    updatedAt: '2025-01-15T09:00:00Z',
    deployedAt: '2025-01-15T09:00:00Z',
    restartCount: 0,
    containerIp: '10.0.100.18',
    aclPreset: 'ACL_PRESET_HTTP_ONLY',
    resources: { cpu: '4', memory: '8GB', disk: '20GB' },
  },
  {
    id: 'app-004',
    name: 'ci-runner',
    username: 'emma',
    containerName: 'emma-container',
    subdomain: 'emma-ci-runner',
    fullDomain: 'emma-ci-runner.containarium.dev',
    port: 8000,
    state: 'APP_STATE_BUILDING',
    dockerImage: '',
    dockerfilePath: './Dockerfile',
    envVars: { CI: 'true' },
    createdAt: '2025-01-15T10:00:00Z',
    updatedAt: '2025-01-15T10:05:00Z',
    restartCount: 0,
    containerIp: '10.0.100.22',
    aclPreset: 'ACL_PRESET_FULL_ISOLATION',
    resources: { cpu: '2', memory: '4GB', disk: '15GB' },
  },
  {
    id: 'app-005',
    name: 'static-docs',
    username: 'alice',
    containerName: 'alice-container',
    subdomain: 'alice-docs',
    fullDomain: 'alice-docs.containarium.dev',
    port: 80,
    state: 'APP_STATE_STOPPED',
    dockerImage: 'nginx:alpine',
    envVars: {},
    createdAt: '2025-01-05T08:00:00Z',
    updatedAt: '2025-01-10T12:00:00Z',
    deployedAt: '2025-01-10T12:00:00Z',
    restartCount: 0,
    containerIp: '10.0.100.12',
    aclPreset: 'ACL_PRESET_HTTP_ONLY',
    resources: { cpu: '0.5', memory: '256MB', disk: '1GB' },
  },
];

// Mock network topology
const mockNetworkNodes: NetworkNode[] = [
  {
    id: 'proxy-caddy',
    type: 'proxy',
    name: 'Caddy (Reverse Proxy)',
    ipAddress: '10.0.100.1',
    state: 'running',
  },
  {
    id: 'alice-container',
    type: 'container',
    name: 'alice',
    ipAddress: '10.0.100.12',
    state: 'running',
    aclName: 'acl-http-only',
  },
  {
    id: 'bob-container',
    type: 'container',
    name: 'bob',
    ipAddress: '10.0.100.15',
    state: 'running',
    aclName: 'acl-permissive',
  },
  {
    id: 'charlie-container',
    type: 'container',
    name: 'charlie',
    ipAddress: '10.0.100.18',
    state: 'running',
    aclName: 'acl-http-only',
  },
  {
    id: 'david-container',
    type: 'container',
    name: 'david',
    ipAddress: '',
    state: 'stopped',
  },
  {
    id: 'emma-container',
    type: 'container',
    name: 'emma',
    ipAddress: '10.0.100.22',
    state: 'running',
    aclName: 'acl-full-isolation',
  },
];

const mockNetworkTopology: NetworkTopology = {
  nodes: mockNetworkNodes,
  edges: [
    // Proxy routes (HTTP/gRPC via Caddy)
    { source: 'proxy-caddy', target: 'alice-container', type: 'route', ports: '8080, 80', protocol: 'HTTP' },
    { source: 'proxy-caddy', target: 'bob-container', type: 'route', ports: '3000', protocol: 'HTTP' },
    { source: 'proxy-caddy', target: 'charlie-container', type: 'route', ports: '5000', protocol: 'HTTP' },
    // emma-container has app building, not yet routed
    { source: 'proxy-caddy', target: 'emma-container', type: 'blocked' },
    // david-container is stopped, no routes
  ],
  networkCidr: '10.0.100.0/24',
  gatewayIp: '10.0.100.1',
};

// Mock proxy routes (includes both app-linked routes and manual routes)
const mockRoutes: ProxyRoute[] = [
  {
    subdomain: 'alice-ml-dashboard',
    fullDomain: 'alice-ml-dashboard.containarium.dev',
    containerIp: '10.0.100.12',
    port: 8080,
    active: true,
    appId: 'app-001',
    appName: 'ml-dashboard',
    username: 'alice',
  },
  {
    subdomain: 'bob-api-server',
    fullDomain: 'bob-api-server.containarium.dev',
    containerIp: '10.0.100.15',
    port: 3000,
    active: true,
    appId: 'app-002',
    appName: 'api-server',
    username: 'bob',
  },
  {
    subdomain: 'charlie-training-monitor',
    fullDomain: 'charlie-training-monitor.containarium.dev',
    containerIp: '10.0.100.18',
    port: 5000,
    active: true,
    appId: 'app-003',
    appName: 'training-monitor',
    username: 'charlie',
  },
  {
    subdomain: 'alice-docs',
    fullDomain: 'alice-docs.containarium.dev',
    containerIp: '10.0.100.12',
    port: 80,
    active: false,
    appId: 'app-005',
    appName: 'static-docs',
    username: 'alice',
  },
  // Manual routes (not linked to apps)
  {
    subdomain: 'test',
    fullDomain: 'test.containarium.dev',
    containerIp: '10.0.100.50',
    port: 8080,
    active: true,
  },
  {
    subdomain: 'staging-api',
    fullDomain: 'staging-api.containarium.dev',
    containerIp: '10.0.100.55',
    port: 3000,
    active: true,
  },
];

// Mock passthrough routes (TCP/UDP port forwarding for gRPC, mTLS, etc.)
const mockPassthroughRoutes: PassthroughRoute[] = [
  {
    externalPort: 50051,
    targetIp: '10.0.100.18',
    targetPort: 50051,
    protocol: 'ROUTE_PROTOCOL_TCP',
    active: true,
    containerName: 'charlie-container',
    description: 'gRPC ML Training Service (mTLS)',
  },
  {
    externalPort: 6379,
    targetIp: '10.0.100.15',
    targetPort: 6379,
    protocol: 'ROUTE_PROTOCOL_TCP',
    active: true,
    containerName: 'bob-container',
    description: 'Redis Cache',
  },
  {
    externalPort: 5432,
    targetIp: '10.0.100.12',
    targetPort: 5432,
    protocol: 'ROUTE_PROTOCOL_TCP',
    active: false,
    containerName: 'alice-container',
    description: 'PostgreSQL Database (disabled)',
  },
];

// Mock DNS records for domain suggestions
const mockDNSRecords: DNSRecord[] = [
  { type: 'A', name: 'alice-ml-dashboard', data: 'alice-ml-dashboard.containarium.dev', ttl: 300 },
  { type: 'A', name: 'bob-api-server', data: 'bob-api-server.containarium.dev', ttl: 300 },
  { type: 'A', name: 'charlie-training-monitor', data: 'charlie-training-monitor.containarium.dev', ttl: 300 },
  { type: 'A', name: 'emma-ci-runner', data: 'emma-ci-runner.containarium.dev', ttl: 300 },
  { type: 'A', name: 'alice-docs', data: 'alice-docs.containarium.dev', ttl: 300 },
  { type: 'A', name: 'test', data: 'test.containarium.dev', ttl: 300 },
  { type: 'A', name: 'staging-api', data: 'staging-api.containarium.dev', ttl: 300 },
  { type: 'CNAME', name: 'www', data: 'containarium.dev', ttl: 300 },
];

const mockBaseDomain = 'containarium.dev';

// Mock ClamAV security data — showcases all scan states
const mockSecurityContainers: ClamavContainerSummary[] = [
  {
    containerName: 'charlie-container',
    username: 'charlie',
    lastScanAt: '2026-03-11T04:15:00Z',
    lastStatus: 'infected',
    lastFindingsCount: 3,
    totalScans: 8,
    infectedScans: 2,
  },
  {
    containerName: 'frank-container',
    username: 'frank',
    lastScanAt: '',
    lastStatus: 'never',
    lastFindingsCount: 0,
    totalScans: 0,
    infectedScans: 0,
  },
  {
    containerName: 'alice-container',
    username: 'alice',
    lastScanAt: '2026-03-11T04:12:00Z',
    lastStatus: 'clean',
    lastFindingsCount: 0,
    totalScans: 12,
    infectedScans: 0,
  },
  {
    containerName: 'bob-container',
    username: 'bob',
    lastScanAt: '2026-03-11T04:10:00Z',
    lastStatus: 'clean',
    lastFindingsCount: 0,
    totalScans: 11,
    infectedScans: 1,
  },
  {
    containerName: 'emma-container',
    username: 'emma',
    lastScanAt: '2026-03-11T04:18:00Z',
    lastStatus: 'clean',
    lastFindingsCount: 0,
    totalScans: 9,
    infectedScans: 0,
  },
  {
    containerName: 'david-container',
    username: 'david',
    lastScanAt: '2026-03-09T20:00:00Z',
    lastStatus: 'clean',
    lastFindingsCount: 0,
    totalScans: 5,
    infectedScans: 0,
  },
];

// Mock scan status — shows an active scan in progress
const mockScanStatus: ScanStatusResponse = {
  jobs: [
    { id: 101, containerName: 'alice-container', username: 'alice', status: 'completed', retryCount: 0, errorMessage: '', createdAt: '2026-03-11T05:30:00Z', startedAt: '2026-03-11T05:30:02Z', completedAt: '2026-03-11T05:32:15Z' },
    { id: 102, containerName: 'bob-container', username: 'bob', status: 'completed', retryCount: 0, errorMessage: '', createdAt: '2026-03-11T05:30:00Z', startedAt: '2026-03-11T05:30:03Z', completedAt: '2026-03-11T05:33:40Z' },
    { id: 103, containerName: 'charlie-container', username: 'charlie', status: 'running', retryCount: 0, errorMessage: '', createdAt: '2026-03-11T05:30:00Z', startedAt: '2026-03-11T05:32:16Z', completedAt: '' },
    { id: 104, containerName: 'emma-container', username: 'emma', status: 'pending', retryCount: 0, errorMessage: '', createdAt: '2026-03-11T05:30:00Z', startedAt: '', completedAt: '' },
    { id: 105, containerName: 'david-container', username: 'david', status: 'pending', retryCount: 0, errorMessage: '', createdAt: '2026-03-11T05:30:00Z', startedAt: '', completedAt: '' },
    { id: 106, containerName: 'frank-container', username: 'frank', status: 'failed', retryCount: 2, errorMessage: 'failed to mount rootfs: container stopped mid-scan', createdAt: '2026-03-11T05:30:00Z', startedAt: '2026-03-11T05:30:04Z', completedAt: '2026-03-11T05:31:10Z' },
  ],
  pendingCount: 2,
  runningCount: 1,
  completedCount: 2,
  failedCount: 1,
};

// Mock traffic stats - simulates route popularity based on requests per minute
const mockTrafficStats: RouteTrafficStats[] = [
  // Most popular - Charlie's training monitor gets heavy API traffic
  { routeId: 'charlie-training-monitor.containarium.dev', requestsPerMin: 12500, bytesPerMin: 85 * 1024 * 1024 },
  // Bob's API server - moderate traffic
  { routeId: 'bob-api-server.containarium.dev', requestsPerMin: 4200, bytesPerMin: 28 * 1024 * 1024 },
  // Alice's ML dashboard - decent traffic
  { routeId: 'alice-ml-dashboard.containarium.dev', requestsPerMin: 1850, bytesPerMin: 12 * 1024 * 1024 },
  // Staging API - some test traffic
  { routeId: 'staging-api.containarium.dev', requestsPerMin: 320, bytesPerMin: 2 * 1024 * 1024 },
  // Test endpoint - minimal traffic
  { routeId: 'test.containarium.dev', requestsPerMin: 45, bytesPerMin: 256 * 1024 },
  // Static docs - inactive (stopped)
  { routeId: 'alice-docs.containarium.dev', requestsPerMin: 0, bytesPerMin: 0 },
  // Passthrough routes
  { routeId: '50051-ROUTE_PROTOCOL_TCP', requestsPerMin: 8500, bytesPerMin: 120 * 1024 * 1024 }, // gRPC ML training - heavy
  { routeId: '6379-ROUTE_PROTOCOL_TCP', requestsPerMin: 25000, bytesPerMin: 45 * 1024 * 1024 }, // Redis - very high ops
  { routeId: '5432-ROUTE_PROTOCOL_TCP', requestsPerMin: 0, bytesPerMin: 0 }, // PostgreSQL - disabled
];

// Mock server for TrafficView
const mockServer = {
  id: 'demo-server',
  name: 'GPU Cluster',
  endpoint: 'https://demo-server.local:50051',
  token: 'mock-token',
  addedAt: Date.now() - 86400000, // Added 1 day ago
};

// ============================================
// Demo Monitoring View (mock Grafana dashboard)
// ============================================

function GaugeChart({ label, value, max, unit, color }: { label: string; value: number; max: number; unit: string; color: string }) {
  const pct = Math.round((value / max) * 100);
  return (
    <Paper sx={{ p: 2, textAlign: 'center', minWidth: 160, flex: 1 }}>
      <Box sx={{ position: 'relative', display: 'inline-flex', mb: 1 }}>
        <CircularProgress variant="determinate" value={pct} size={80} thickness={6}
          sx={{ color, '& .MuiCircularProgress-circle': { strokeLinecap: 'round' } }} />
        <Box sx={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Typography variant="body2" fontWeight="bold">{pct}%</Typography>
        </Box>
      </Box>
      <Typography variant="body2" fontWeight={500}>{label}</Typography>
      <Typography variant="caption" color="text.secondary">{value}{unit} / {max}{unit}</Typography>
    </Paper>
  );
}

function SparkBar({ label, values, color }: { label: string; values: number[]; color: string }) {
  const maxVal = Math.max(...values, 1);
  return (
    <Paper sx={{ p: 2, flex: 1, minWidth: 200 }}>
      <Typography variant="body2" fontWeight={500} gutterBottom>{label}</Typography>
      <Box sx={{ display: 'flex', alignItems: 'flex-end', gap: '2px', height: 48 }}>
        {values.map((v, i) => (
          <Box key={i} sx={{ flex: 1, bgcolor: color, borderRadius: '2px 2px 0 0', height: `${(v / maxVal) * 100}%`, minHeight: 2, opacity: 0.5 + (i / values.length) * 0.5 }} />
        ))}
      </Box>
      <Typography variant="caption" color="text.secondary">Last 30 minutes</Typography>
    </Paper>
  );
}

function DemoMonitoringView() {
  // Mock per-container CPU sparkline data (30 data points each)
  const cpuSpark = [12, 15, 22, 18, 35, 42, 38, 45, 52, 48, 55, 60, 58, 62, 55, 50, 48, 52, 58, 65, 70, 68, 72, 75, 70, 65, 60, 58, 55, 52];
  const memSpark = [40, 41, 42, 42, 43, 44, 45, 46, 48, 50, 52, 55, 58, 60, 62, 64, 65, 65, 64, 63, 62, 61, 60, 60, 59, 58, 58, 57, 57, 56];
  const netSpark = [5, 8, 12, 15, 22, 35, 28, 18, 42, 55, 38, 25, 32, 45, 50, 48, 35, 28, 22, 15, 18, 25, 32, 28, 22, 18, 15, 12, 10, 8];

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <MonitorHeartIcon />
          <Typography variant="h5">Monitoring</Typography>
        </Box>
        <IconButton size="small"><RefreshIcon /></IconButton>
      </Box>

      {/* System Gauges */}
      <Typography variant="subtitle2" color="text.secondary" gutterBottom>System Resources</Typography>
      <Stack direction="row" spacing={2} sx={{ mb: 3, flexWrap: 'wrap' }}>
        <GaugeChart label="CPU Load (1m)" value={18.5} max={32} unit=" cores" color="#1976d2" />
        <GaugeChart label="Memory" value={80} max={128} unit=" GB" color="#9c27b0" />
        <GaugeChart label="Disk" value={800} max={2048} unit=" GB" color="#ed6c02" />
      </Stack>

      {/* Container counts */}
      <Stack direction="row" spacing={2} sx={{ mb: 3 }}>
        <Paper sx={{ p: 2, textAlign: 'center', flex: 1 }}>
          <Typography variant="h3" color="success.main" fontWeight="bold">5</Typography>
          <Typography variant="body2" color="text.secondary">Running</Typography>
        </Paper>
        <Paper sx={{ p: 2, textAlign: 'center', flex: 1 }}>
          <Typography variant="h3" color="text.secondary" fontWeight="bold">1</Typography>
          <Typography variant="body2" color="text.secondary">Stopped</Typography>
        </Paper>
        <Paper sx={{ p: 2, textAlign: 'center', flex: 1 }}>
          <Typography variant="h3" color="primary.main" fontWeight="bold">6</Typography>
          <Typography variant="body2" color="text.secondary">Total</Typography>
        </Paper>
      </Stack>

      {/* Sparkline charts */}
      <Typography variant="subtitle2" color="text.secondary" gutterBottom>Cluster Activity</Typography>
      <Stack direction="row" spacing={2} sx={{ mb: 3, flexWrap: 'wrap' }}>
        <SparkBar label="CPU Usage (%)" values={cpuSpark} color="#1976d2" />
        <SparkBar label="Memory Usage (%)" values={memSpark} color="#9c27b0" />
        <SparkBar label="Network I/O (MB/s)" values={netSpark} color="#2e7d32" />
      </Stack>

      {/* Per-container table */}
      <Typography variant="subtitle2" color="text.secondary" gutterBottom>Per-Container Metrics</Typography>
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Container</TableCell>
              <TableCell align="right">CPU (cores)</TableCell>
              <TableCell align="right">Memory</TableCell>
              <TableCell align="right">Disk</TableCell>
              <TableCell align="right">Network Rx</TableCell>
              <TableCell align="right">Network Tx</TableCell>
              <TableCell align="right">Processes</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {[
              { name: 'alice-container', cpu: '3.2 / 8', mem: '12.0 / 16 GB', disk: '65 / 100 GB', rx: '2.5 GB', tx: '1.2 GB', procs: 156 },
              { name: 'charlie-container', cpu: '14.5 / 16', mem: '28.0 / 32 GB', disk: '145 / 200 GB', rx: '15.0 GB', tx: '8.0 GB', procs: 312 },
              { name: 'bob-container', cpu: '0.9 / 4', mem: '3.2 / 8 GB', disk: '22 / 50 GB', rx: '850 MB', tx: '320 MB', procs: 42 },
              { name: 'emma-container', cpu: '0.5 / 4', mem: '1.8 / 8 GB', disk: '8 / 50 GB', rx: '120 MB', tx: '45 MB', procs: 28 },
              { name: 'frank-container', cpu: '0.0 / 8', mem: '0.2 / 16 GB', disk: '2 / 100 GB', rx: '0 MB', tx: '0 MB', procs: 0 },
            ].map(row => (
              <TableRow key={row.name} hover>
                <TableCell>{row.name}</TableCell>
                <TableCell align="right">{row.cpu}</TableCell>
                <TableCell align="right">{row.mem}</TableCell>
                <TableCell align="right">{row.disk}</TableCell>
                <TableCell align="right">{row.rx}</TableCell>
                <TableCell align="right">{row.tx}</TableCell>
                <TableCell align="right">{row.procs}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
        In production, this tab embeds a live Grafana dashboard via iframe.
      </Typography>
    </Box>
  );
}

// ============================================
// Demo Security View (self-contained, no API calls)
// ============================================

function DemoStatusChip({ status }: { status: string }) {
  switch (status) {
    case 'clean':
      return <Chip label="Clean" color="success" size="small" />;
    case 'infected':
      return <Chip label="Infected" color="error" size="small" />;
    case 'never':
      return <Chip label="Never Scanned" size="small" sx={{ bgcolor: 'grey.300' }} />;
    default:
      return <Chip label={status} size="small" />;
  }
}

function DemoSummaryCard({ title, value, color }: { title: string; value: number; color: string }) {
  return (
    <Paper sx={{ p: 2, textAlign: 'center', minWidth: 140 }}>
      <Typography variant="h4" sx={{ color, fontWeight: 'bold' }}>
        {value}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        {title}
      </Typography>
    </Paper>
  );
}

function DemoScanAction({ containerName, scanStatus }: { containerName: string; scanStatus: ScanStatusResponse }) {
  const job = scanStatus.jobs.find(j => j.containerName === containerName && (j.status === 'pending' || j.status === 'running'));
  if (job?.status === 'pending') {
    return (
      <Tooltip title="Queued — waiting for available worker">
        <HourglassEmptyIcon fontSize="small" color="action" />
      </Tooltip>
    );
  }
  if (job?.status === 'running') {
    return (
      <Tooltip title="Scanning...">
        <CircularProgress size={18} />
      </Tooltip>
    );
  }
  const recentJob = scanStatus.jobs.find(j => j.containerName === containerName);
  if (recentJob?.status === 'failed') {
    return (
      <Tooltip title={`Failed: ${recentJob.errorMessage}`}>
        <IconButton size="small"><ErrorOutlineIcon fontSize="small" color="error" /></IconButton>
      </Tooltip>
    );
  }
  if (recentJob?.status === 'completed') {
    return (
      <Tooltip title="Scan completed — click to re-scan">
        <IconButton size="small"><CheckCircleOutlineIcon fontSize="small" color="success" /></IconButton>
      </Tooltip>
    );
  }
  return (
    <Tooltip title="Trigger scan">
      <IconButton size="small"><ScannerIcon fontSize="small" /></IconButton>
    </Tooltip>
  );
}

function formatDate(iso: string): string {
  if (!iso) return 'Never';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function DemoSecurityView() {
  const summary = {
    totalContainers: mockSecurityContainers.length,
    cleanContainers: mockSecurityContainers.filter(c => c.lastStatus === 'clean').length,
    infectedContainers: mockSecurityContainers.filter(c => c.lastStatus === 'infected').length,
    neverScannedContainers: mockSecurityContainers.filter(c => c.lastStatus === 'never').length,
  };
  const total = mockScanStatus.completedCount + mockScanStatus.failedCount + mockScanStatus.runningCount + mockScanStatus.pendingCount;
  const progress = total > 0 ? ((mockScanStatus.completedCount + mockScanStatus.failedCount) / total) * 100 : 0;
  const today = new Date().toISOString().slice(0, 10);
  const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

  // Sort: infected first, then never, then clean
  const sorted = [...mockSecurityContainers].sort((a, b) => {
    const order: Record<string, number> = { infected: 0, never: 1, clean: 2 };
    return (order[a.lastStatus] ?? 3) - (order[b.lastStatus] ?? 3);
  });

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <ShieldIcon />
          <Typography variant="h5">Security Scanning</Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Button variant="contained" size="small" startIcon={<CircularProgress size={16} color="inherit" />} disabled>
            Scan All
          </Button>
          <IconButton size="small"><RefreshIcon /></IconButton>
        </Box>
      </Box>

      {/* Summary Cards */}
      <Stack direction="row" spacing={2} sx={{ mb: 3, flexWrap: 'wrap' }}>
        <DemoSummaryCard title="Total Containers" value={summary.totalContainers} color="text.primary" />
        <DemoSummaryCard title="Clean" value={summary.cleanContainers} color="success.main" />
        <DemoSummaryCard title="Infected" value={summary.infectedContainers} color="error.main" />
        <DemoSummaryCard title="Never Scanned" value={summary.neverScannedContainers} color="text.secondary" />
      </Stack>

      {/* Scan Progress */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>Scan Progress</Typography>
        <Box sx={{ mb: 1 }}>
          <LinearProgress variant="determinate" value={progress} />
        </Box>
        <Stack direction="row" spacing={2}>
          <Typography variant="body2" color="text.secondary">Pending: {mockScanStatus.pendingCount}</Typography>
          <Typography variant="body2" color="info.main">Running: {mockScanStatus.runningCount}</Typography>
          <Typography variant="body2" color="success.main">Completed: {mockScanStatus.completedCount}</Typography>
          <Typography variant="body2" color="error.main">Failed: {mockScanStatus.failedCount}</Typography>
        </Stack>
      </Paper>

      {/* CSV Download Section */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>Download Scan Reports</Typography>
        <Stack direction="row" spacing={2} alignItems="center">
          <TextField type="date" label="Start Date" value={weekAgo} size="small" InputLabelProps={{ shrink: true }} />
          <TextField type="date" label="End Date" value={today} size="small" InputLabelProps={{ shrink: true }} />
          <Button variant="contained" startIcon={<DownloadIcon />} size="small">Download CSV</Button>
        </Stack>
      </Paper>

      {/* Container Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Container</TableCell>
              <TableCell>Username</TableCell>
              <TableCell>Last Scan</TableCell>
              <TableCell>Status</TableCell>
              <TableCell align="right">Findings</TableCell>
              <TableCell align="right">Total Scans</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {sorted.map((container) => (
              <TableRow key={container.containerName} hover>
                <TableCell>{container.containerName}</TableCell>
                <TableCell>{container.username}</TableCell>
                <TableCell>{formatDate(container.lastScanAt)}</TableCell>
                <TableCell><DemoStatusChip status={container.lastStatus} /></TableCell>
                <TableCell align="right">{container.lastFindingsCount}</TableCell>
                <TableCell align="right">{container.totalScans}</TableCell>
                <TableCell align="right">
                  <DemoScanAction containerName={container.containerName} scanStatus={mockScanStatus} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
        Summary generated at: {formatDate(new Date().toISOString())}
      </Typography>
    </Box>
  );
}

// ============================================
// Tab Panel
// ============================================

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box>{children}</Box>}
    </div>
  );
}

export default function DemoPage() {
  const [tabIndex, setTabIndex] = useState(0);
  const [includeStopped, setIncludeStopped] = useState(true);
  const [labelEditorOpen, setLabelEditorOpen] = useState(false);
  const [selectedContainer, setSelectedContainer] = useState<{username: string, labels: Record<string, string>} | null>(null);

  const handleEditLabels = (username: string, labels: Record<string, string>) => {
    setSelectedContainer({ username, labels });
    setLabelEditorOpen(true);
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AppBar onAddServer={() => {}} />

      <Box sx={{ bgcolor: 'primary.main', color: 'white', py: 1, px: 2 }}>
        <Typography variant="body2">
          Demo Mode - Showing mock data for UI preview
        </Typography>
      </Box>

      <Box sx={{ borderBottom: 1, borderColor: 'divider', px: 2, py: 1, bgcolor: 'grey.50' }}>
        <Typography variant="body1" sx={{ fontWeight: 500 }}>
          GPU Cluster (demo-server.local)
        </Typography>
      </Box>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', bgcolor: 'background.paper' }}>
        <Tabs value={tabIndex} onChange={(_, v) => setTabIndex(v)} sx={{ px: 2 }}>
          <Tab icon={<DnsIcon />} iconPosition="start" label="Containers" />
          <Tab icon={<AppsIcon />} iconPosition="start" label="Apps" />
          <Tab icon={<HubIcon />} iconPosition="start" label="Network" />
          <Tab icon={<TimelineIcon />} iconPosition="start" label="Traffic" />
          <Tab icon={<MonitorHeartIcon />} iconPosition="start" label="Monitoring" />
          <Tab icon={<ShieldIcon />} iconPosition="start" label="Security" />
        </Tabs>
      </Box>

      {/* Container View */}
      <TabPanel value={tabIndex} index={0}>
        <ContainerTopology
          containers={mockContainers}
          metricsMap={mockMetricsMap}
          systemInfo={mockSystemInfo}
          isLoading={false}
          error={null}
          onCreateContainer={() => {}}
          onDeleteContainer={() => {}}
          onStartContainer={() => {}}
          onStopContainer={() => {}}
          onTerminalContainer={() => {}}
          onEditFirewall={() => {}}
          onEditLabels={handleEditLabels}
          onRefresh={() => {}}
        />
      </TabPanel>

      {/* Apps View */}
      <TabPanel value={tabIndex} index={1}>
        <AppsView
          apps={mockApps}
          isLoading={false}
          error={null}
          onStopApp={async () => {}}
          onStartApp={async () => {}}
          onRestartApp={async () => {}}
          onDeleteApp={async () => {}}
          onViewLogs={() => {}}
          onRefresh={() => {}}
        />
      </TabPanel>

      {/* Network Topology View */}
      <TabPanel value={tabIndex} index={2}>
        <NetworkTopologyView
          topology={mockNetworkTopology}
          routes={mockRoutes}
          passthroughRoutes={mockPassthroughRoutes}
          dnsRecords={mockDNSRecords}
          baseDomain={mockBaseDomain}
          isLoading={false}
          error={null}
          includeStopped={includeStopped}
          onIncludeStoppedChange={setIncludeStopped}
          onAddRoute={async (domain, targetIp, targetPort, protocol) => {
            console.log('Demo: Would add proxy route:', { domain, targetIp, targetPort, protocol });
          }}
          onDeleteRoute={async (domain) => {
            console.log('Demo: Would delete proxy route:', domain);
          }}
          onToggleRoute={async (domain, enabled) => {
            console.log('Demo: Would toggle proxy route:', { domain, enabled });
          }}
          onAddPassthroughRoute={async (externalPort, targetIp, targetPort, protocol, containerName) => {
            console.log('Demo: Would add passthrough route:', { externalPort, targetIp, targetPort, protocol, containerName });
          }}
          onDeletePassthroughRoute={async (externalPort, protocol) => {
            console.log('Demo: Would delete passthrough route:', { externalPort, protocol });
          }}
          onTogglePassthroughRoute={async (externalPort, protocol, enabled) => {
            console.log('Demo: Would toggle passthrough route:', { externalPort, protocol, enabled });
          }}
          onRefresh={() => {}}
        />
      </TabPanel>

      {/* Traffic View */}
      <TabPanel value={tabIndex} index={3}>
        <TrafficView
          server={mockServer}
          containers={mockContainers}
          proxyRoutes={mockRoutes}
          passthroughRoutes={mockPassthroughRoutes}
          trafficStats={mockTrafficStats}
          onDateRangeChange={(start, end) => {
            console.log('Demo: Would query traffic for date range:', { start, end });
          }}
        />
      </TabPanel>

      {/* Monitoring View */}
      <TabPanel value={tabIndex} index={4}>
        <DemoMonitoringView />
      </TabPanel>

      {/* Security View */}
      <TabPanel value={tabIndex} index={5}>
        <DemoSecurityView />
      </TabPanel>

      {/* Label Editor Dialog */}
      {selectedContainer && (
        <LabelEditorDialog
          open={labelEditorOpen}
          onClose={() => {
            setLabelEditorOpen(false);
            setSelectedContainer(null);
          }}
          containerName={`${selectedContainer.username}-container`}
          username={selectedContainer.username}
          currentLabels={selectedContainer.labels}
          onSave={async (labels) => {
            console.log('Demo: Would save labels:', labels);
          }}
          onRemove={async (key) => {
            console.log('Demo: Would remove label:', key);
          }}
        />
      )}
    </Box>
  );
}
