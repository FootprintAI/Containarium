'use client';

import { useState } from 'react';
import { Box, Typography, Tabs, Tab } from '@mui/material';
import AppBar from '@/src/components/layout/AppBar';
import ContainerTopology from '@/src/components/containers/ContainerTopology';
import LabelEditorDialog from '@/src/components/containers/LabelEditorDialog';
import AppsView from '@/src/components/apps/AppsView';
import NetworkTopologyView from '@/src/components/network/NetworkTopologyView';
import { Container, ContainerMetricsWithRate, SystemInfo } from '@/src/types/container';
import { App, NetworkTopology, ProxyRoute, NetworkNode } from '@/src/types/app';

// Mock system info for system resources card
const mockSystemInfo: SystemInfo = {
  version: '0.3.0',
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
    dockerEnabled: true,
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
    dockerEnabled: true,
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
    dockerEnabled: true,
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
    dockerEnabled: false,
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
    dockerEnabled: true,
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
    dockerEnabled: true,
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
    { source: 'proxy-caddy', target: 'alice-container', type: 'route', ports: '8080' },
    { source: 'proxy-caddy', target: 'bob-container', type: 'route', ports: '3000' },
    { source: 'proxy-caddy', target: 'charlie-container', type: 'route', ports: '5000' },
    { source: 'proxy-caddy', target: 'emma-container', type: 'blocked' },
  ],
  networkCidr: '10.0.100.0/24',
  gatewayIp: '10.0.100.1',
};

// Mock proxy routes
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
];

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
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={tabIndex} onChange={(_, v) => setTabIndex(v)}>
          <Tab label="Containers" />
          <Tab label="Apps" />
          <Tab label="Network" />
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
          isLoading={false}
          error={null}
          includeStopped={includeStopped}
          onIncludeStoppedChange={setIncludeStopped}
          onRefresh={() => {}}
        />
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
