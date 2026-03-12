'use client';

import { useState, useMemo, useEffect, useCallback } from 'react';
import dynamic from 'next/dynamic';
import { usePathname } from 'next/navigation';
import { Box, Typography, CircularProgress, Tabs, Tab } from '@mui/material';
import DnsIcon from '@mui/icons-material/Dns';
import AppsIcon from '@mui/icons-material/Apps';
import HubIcon from '@mui/icons-material/Hub';
import TimelineIcon from '@mui/icons-material/Timeline';
import InsightsIcon from '@mui/icons-material/Insights';
import ShieldIcon from '@mui/icons-material/Shield';
import PolicyIcon from '@mui/icons-material/Policy';
import AppBar from '@/src/components/layout/AppBar';
import ServerTabs from '@/src/components/layout/ServerTabs';
import AddServerDialog from '@/src/components/servers/AddServerDialog';
import ContainerTopology from '@/src/components/containers/ContainerTopology';
import CreateContainerDialog from '@/src/components/containers/CreateContainerDialog';
import DeleteConfirmDialog from '@/src/components/containers/DeleteConfirmDialog';
import LabelEditorDialog from '@/src/components/containers/LabelEditorDialog';
import ResizeContainerDialog from '@/src/components/containers/ResizeContainerDialog';
import CollaboratorsDialog from '@/src/components/containers/CollaboratorsDialog';
import AppsView from '@/src/components/apps/AppsView';
import NetworkTopologyView from '@/src/components/network/NetworkTopologyView';
import FirewallEditor from '@/src/components/network/FirewallEditor';
import TrafficView from '@/src/components/traffic/TrafficView';
import MonitoringView from '@/src/components/monitoring/MonitoringView';
import SecurityView from '@/src/components/security/SecurityView';
import AuditView from '@/src/components/audit/AuditView';
import { useServers } from '@/src/lib/hooks/useServers';
import { useContainers, CreateContainerProgress } from '@/src/lib/hooks/useContainers';
import { useMetrics } from '@/src/lib/hooks/useMetrics';
import { useApps } from '@/src/lib/hooks/useApps';
import { useRoutes, usePassthroughRoutes, useNetworkTopology, useContainerACL, useACLPresets, useDNSRecords } from '@/src/lib/hooks/useNetwork';
import { useCollaborators } from '@/src/lib/hooks/useCollaborators';
import { CreateContainerRequest, ContainerMetricsWithRate } from '@/src/types/container';
import { Server } from '@/src/types/server';
import { ACLPreset } from '@/src/types/app';

// Dynamic import for TerminalDialog to avoid SSR issues with xterm
const TerminalDialog = dynamic(
  () => import('@/src/components/containers/TerminalDialog'),
  { ssr: false }
);

const TAB_PATHS = ['/containers/', '/apps/', '/network/', '/traffic/', '/monitoring/', '/security/', '/audit/'] as const;
const TAB_INDICES: Record<string, number> = {
  '/': 0,
  '/containers/': 0,
  '/apps/': 1,
  '/network/': 2,
  '/traffic/': 3,
  '/monitoring/': 4,
  '/security/': 5,
  '/audit/': 6,
};

export default function Home() {
  const pathname = usePathname();

  const {
    servers,
    activeServer,
    activeServerId,
    setActiveServerId,
    addServer,
    removeServer,
    updateServer,
    isLoading: serversLoading,
  } = useServers();

  // Derive tab from URL path
  const currentPath = (pathname || '/').replace(/\/?$/, '/');
  const tabFromPath = TAB_INDICES[currentPath] ?? 0;
  const [viewTab, setViewTabState] = useState(tabFromPath);

  // Handle browser back/forward
  useEffect(() => {
    const onPopState = () => {
      const path = window.location.pathname.replace(/^\/webui/, '').replace(/\/?$/, '/');
      setViewTabState(TAB_INDICES[path] ?? 0);
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  // Update tab + URL without full page reload
  const setViewTab = useCallback((newTab: number) => {
    setViewTabState(newTab);
    const path = '/webui' + (TAB_PATHS[newTab] || '/containers/');
    window.history.pushState(null, '', path);
  }, []);

  // Container hooks
  const {
    containers,
    coreServices,
    systemInfo,
    isLoading: containersLoading,
    error: containersError,
    createContainer,
    deleteContainer,
    startContainer,
    stopContainer,
    resizeContainer,
    cleanupDisk,
    setLabels,
    removeLabel,
    refresh: refreshContainers,
  } = useContainers(activeServer);

  // Metrics hook
  const hasRunningContainers = containers.some(c => c.state === 'Running');
  const { metrics } = useMetrics(activeServer, hasRunningContainers);

  // Apps hooks
  const {
    apps,
    isLoading: appsLoading,
    error: appsError,
    stopApp,
    startApp,
    restartApp,
    deleteApp,
    refresh: refreshApps,
  } = useApps(activeServer);

  // Network hooks
  const [includeStopped, setIncludeStopped] = useState(false);
  const { routes, isLoading: routesLoading, error: routesError, addRoute, deleteRoute, updateRoute, refresh: refreshRoutes } = useRoutes(activeServer);
  const { routes: passthroughRoutes, isLoading: passthroughLoading, addPassthroughRoute, deletePassthroughRoute, updatePassthroughRoute, refresh: refreshPassthrough } = usePassthroughRoutes(activeServer);
  const { topology, isLoading: topologyLoading, error: topologyError, refresh: refreshTopology } = useNetworkTopology(activeServer, includeStopped);
  const { presets, isLoading: presetsLoading } = useACLPresets(activeServer);
  const { records: dnsRecords, baseDomain, refresh: refreshDNS } = useDNSRecords(activeServer);

  // Firewall editor state - now per container (DevBox), not per app
  const [firewallEditorOpen, setFirewallEditorOpen] = useState(false);
  const [selectedContainer, setSelectedContainer] = useState<string | null>(null);
  const { acl, isLoading: aclLoading, updateACL } = useContainerACL(
    activeServer,
    selectedContainer || ''
  );

  // Collaborator state and hooks
  const [collaboratorContainer, setCollaboratorContainer] = useState<string | null>(null);
  const {
    collaborators,
    isLoading: collaboratorsLoading,
    addCollaborator,
    removeCollaborator,
  } = useCollaborators(activeServer, collaboratorContainer);

  // Convert metrics array to a map by container name for easy lookup
  const metricsMap = useMemo(() => {
    const map: Record<string, ContainerMetricsWithRate> = {};
    for (const m of metrics) {
      map[m.name] = m;
    }
    return map;
  }, [metrics]);

  // Dialog states
  const [serverDialogOpen, setServerDialogOpen] = useState(false);
  const [editingServer, setEditingServer] = useState<Server | null>(null);
  const [createContainerOpen, setCreateContainerOpen] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<{ open: boolean; containerName: string }>({
    open: false,
    containerName: '',
  });
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [terminalUsername, setTerminalUsername] = useState('');
  const [labelEditorOpen, setLabelEditorOpen] = useState(false);
  const [labelEditorContainer, setLabelEditorContainer] = useState<{username: string, labels: Record<string, string>} | null>(null);
  const [resizeDialogOpen, setResizeDialogOpen] = useState(false);
  const [resizeTarget, setResizeTarget] = useState<{username: string, cpu: string, memory: string, disk: string} | null>(null);

  // Server handlers
  const handleAddServer = async (name: string, endpoint: string, token: string) => {
    await addServer(name, endpoint, token);
  };

  const handleUpdateServer = async (serverId: string, name: string, endpoint: string, token: string) => {
    await updateServer(serverId, name, endpoint, token);
  };

  const handleEditServer = (serverId: string) => {
    const server = servers.find(s => s.id === serverId);
    if (server) {
      setEditingServer(server);
      setServerDialogOpen(true);
    }
  };

  const handleCloseServerDialog = () => {
    setServerDialogOpen(false);
    setEditingServer(null);
  };

  // Container handlers
  const handleCreateContainer = async (
    request: CreateContainerRequest,
    onProgress?: (progress: CreateContainerProgress) => void
  ) => {
    await createContainer(request, onProgress);
  };

  const handleDeleteContainer = (username: string) => {
    setDeleteConfirm({ open: true, containerName: username });
  };

  const handleConfirmDelete = async () => {
    await deleteContainer(deleteConfirm.containerName, true);
  };

  const handleOpenTerminal = (username: string) => {
    setTerminalUsername(username);
    setTerminalOpen(true);
  };

  const handleCloseTerminal = () => {
    setTerminalOpen(false);
    setTerminalUsername('');
  };

  // Label editor handlers
  const handleEditLabels = (username: string, labels: Record<string, string>) => {
    setLabelEditorContainer({ username, labels });
    setLabelEditorOpen(true);
  };

  const handleCloseLabelEditor = () => {
    setLabelEditorOpen(false);
    setLabelEditorContainer(null);
  };

  // Resize handlers
  const handleOpenResize = (username: string, currentResources: { cpu: string; memory: string; disk: string }) => {
    setResizeTarget({ username, ...currentResources });
    setResizeDialogOpen(true);
  };

  // Collaborator handlers
  const handleManageCollaborators = (username: string) => {
    setCollaboratorContainer(username);
  };

  const handleCloseCollaborators = () => {
    setCollaboratorContainer(null);
  };

  const handleCloseResize = () => {
    setResizeDialogOpen(false);
    setResizeTarget(null);
  };

  const handleResize = async (resources: { cpu?: string; memory?: string; disk?: string }) => {
    if (!resizeTarget) return;
    await resizeContainer(resizeTarget.username, resources);
  };

  // App handlers
  const handleStopApp = async (username: string, appName: string) => {
    await stopApp(username, appName);
  };

  const handleStartApp = async (username: string, appName: string) => {
    await startApp(username, appName);
  };

  const handleRestartApp = async (username: string, appName: string) => {
    await restartApp(username, appName);
  };

  const handleDeleteApp = async (username: string, appName: string) => {
    await deleteApp(username, appName, false);
  };

  // Firewall handlers - now per container (DevBox), not per app
  const handleEditContainerFirewall = (username: string) => {
    setSelectedContainer(username);
    setFirewallEditorOpen(true);
  };

  const handleSaveFirewall = async (preset: ACLPreset) => {
    if (selectedContainer) {
      await updateACL(preset);
    }
  };

  // Network refresh handler
  const handleRefreshNetwork = () => {
    refreshRoutes();
    refreshTopology();
    refreshDNS();
  };

  if (serversLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AppBar onAddServer={() => setServerDialogOpen(true)} />

      <ServerTabs
        servers={servers}
        activeServerId={activeServerId}
        onServerChange={setActiveServerId}
        onRemoveServer={removeServer}
        onEditServer={handleEditServer}
      />

      {servers.length === 0 ? (
        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}>
          <Typography variant="h5" color="text.secondary" gutterBottom>
            No servers added
          </Typography>
          <Typography color="text.secondary">
            Click "Add Server" to connect to a Containarium server
          </Typography>
        </Box>
      ) : activeServer ? (
        <>
          {/* View Tabs */}
          <Box sx={{ borderBottom: 1, borderColor: 'divider', bgcolor: 'background.paper' }}>
            <Tabs
              value={viewTab}
              onChange={(_, newValue) => setViewTab(newValue)}
              sx={{ px: 2 }}
            >
              <Tab icon={<DnsIcon />} iconPosition="start" label="Containers" />
              <Tab icon={<AppsIcon />} iconPosition="start" label="Apps" />
              <Tab icon={<HubIcon />} iconPosition="start" label="Network" />
              <Tab icon={<TimelineIcon />} iconPosition="start" label="Traffic" />
              <Tab icon={<InsightsIcon />} iconPosition="start" label="Monitoring" />
              <Tab icon={<ShieldIcon />} iconPosition="start" label="Security" />
              <Tab icon={<PolicyIcon />} iconPosition="start" label="Audit" />
            </Tabs>
          </Box>

          {/* Tab Content */}
          <Box sx={{ flex: 1, overflow: 'auto' }}>
            {viewTab === 0 && (
              <ContainerTopology
                containers={containers}
                coreServices={coreServices}
                metricsMap={metricsMap}
                systemInfo={systemInfo}
                isLoading={containersLoading}
                error={containersError as Error | null}
                onCreateContainer={() => setCreateContainerOpen(true)}
                onDeleteContainer={handleDeleteContainer}
                onStartContainer={startContainer}
                onStopContainer={stopContainer}
                onTerminalContainer={handleOpenTerminal}
                onEditFirewall={handleEditContainerFirewall}
                onEditLabels={handleEditLabels}
                onResize={handleOpenResize}
                onManageCollaborators={handleManageCollaborators}
                onRefresh={refreshContainers}
              />
            )}

            {viewTab === 1 && (
              <AppsView
                apps={apps}
                isLoading={appsLoading}
                error={appsError as Error | null}
                onStopApp={handleStopApp}
                onStartApp={handleStartApp}
                onRestartApp={handleRestartApp}
                onDeleteApp={handleDeleteApp}
                onRefresh={refreshApps}
              />
            )}

            {viewTab === 2 && (
              <NetworkTopologyView
                topology={topology}
                routes={routes}
                passthroughRoutes={passthroughRoutes}
                dnsRecords={dnsRecords}
                baseDomain={baseDomain}
                isLoading={topologyLoading || routesLoading || passthroughLoading}
                error={(topologyError || routesError) as Error | null}
                includeStopped={includeStopped}
                onIncludeStoppedChange={setIncludeStopped}
                onAddRoute={async (domain, targetIp, targetPort, protocol) => {
                  await addRoute(domain, targetIp, targetPort, protocol);
                }}
                onDeleteRoute={async (domain) => {
                  await deleteRoute(domain);
                }}
                onToggleRoute={async (domain, enabled) => {
                  await updateRoute(domain, { active: enabled });
                }}
                onAddPassthroughRoute={async (externalPort, targetIp, targetPort, protocol, containerName) => {
                  await addPassthroughRoute(externalPort, targetIp, targetPort, protocol, containerName);
                }}
                onDeletePassthroughRoute={async (externalPort, protocol) => {
                  await deletePassthroughRoute(externalPort, protocol);
                }}
                onTogglePassthroughRoute={async (externalPort, protocol, enabled) => {
                  await updatePassthroughRoute(externalPort, protocol, { active: enabled });
                }}
                onRefresh={() => {
                  handleRefreshNetwork();
                  refreshPassthrough();
                }}
              />
            )}

            {viewTab === 3 && (
              <TrafficView
                server={activeServer}
                containers={containers}
                proxyRoutes={routes}
                passthroughRoutes={passthroughRoutes}
              />
            )}

            {viewTab === 4 && (
              <MonitoringView server={activeServer} />
            )}

            {viewTab === 5 && (
              <SecurityView server={activeServer} />
            )}

            {viewTab === 6 && (
              <AuditView server={activeServer} />
            )}
          </Box>
        </>
      ) : (
        <Box sx={{ flex: 1, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
          <Typography color="text.secondary">
            Select a server to view containers
          </Typography>
        </Box>
      )}

      {/* Dialogs */}
      <AddServerDialog
        open={serverDialogOpen}
        onClose={handleCloseServerDialog}
        onAdd={handleAddServer}
        onUpdate={handleUpdateServer}
        editServer={editingServer}
      />

      <CreateContainerDialog
        open={createContainerOpen}
        onClose={() => setCreateContainerOpen(false)}
        onSubmit={handleCreateContainer}
        networkCidr={systemInfo?.networkCidr}
      />

      <DeleteConfirmDialog
        open={deleteConfirm.open}
        containerName={deleteConfirm.containerName}
        onClose={() => setDeleteConfirm({ open: false, containerName: '' })}
        onConfirm={handleConfirmDelete}
      />

      {activeServer && terminalOpen && (
        <TerminalDialog
          open={terminalOpen}
          onClose={handleCloseTerminal}
          containerName={terminalUsername + '-container'}
          username={terminalUsername}
          serverEndpoint={activeServer.endpoint}
          token={activeServer.token}
        />
      )}

      {/* Firewall Editor - per container (DevBox) */}
      <FirewallEditor
        open={firewallEditorOpen}
        onClose={() => {
          setFirewallEditorOpen(false);
          setSelectedContainer(null);
        }}
        acl={acl || null}
        presets={presets}
        isLoading={aclLoading || presetsLoading}
        appName={selectedContainer ? `${selectedContainer}-container` : ''}
        username={selectedContainer || ''}
        onSave={handleSaveFirewall}
      />

      {/* Label Editor Dialog */}
      {labelEditorContainer && (
        <LabelEditorDialog
          open={labelEditorOpen}
          onClose={handleCloseLabelEditor}
          containerName={`${labelEditorContainer.username}-container`}
          username={labelEditorContainer.username}
          currentLabels={labelEditorContainer.labels}
          onSave={async (labels) => {
            await setLabels(labelEditorContainer.username, labels);
          }}
          onRemove={async (key) => {
            await removeLabel(labelEditorContainer.username, key);
          }}
        />
      )}

      {/* Resize Container Dialog */}
      {resizeTarget && (
        <ResizeContainerDialog
          open={resizeDialogOpen}
          onClose={handleCloseResize}
          containerName={`${resizeTarget.username}-container`}
          username={resizeTarget.username}
          currentCpu={resizeTarget.cpu}
          currentMemory={resizeTarget.memory}
          currentDisk={resizeTarget.disk}
          memoryUsageBytes={metricsMap[`${resizeTarget.username}-container`]?.memoryUsageBytes}
          diskUsageBytes={metricsMap[`${resizeTarget.username}-container`]?.diskUsageBytes}
          onResize={handleResize}
          onCleanupDisk={async () => {
            if (!resizeTarget) throw new Error('No container selected');
            return cleanupDisk(resizeTarget.username);
          }}
        />
      )}

      {/* Collaborators Dialog */}
      {collaboratorContainer && (
        <CollaboratorsDialog
          open={!!collaboratorContainer}
          onClose={handleCloseCollaborators}
          ownerUsername={collaboratorContainer}
          collaborators={collaborators}
          isLoading={collaboratorsLoading}
          onAdd={async (req) => {
            const result = await addCollaborator(req);
            return { sshCommand: result.sshCommand };
          }}
          onRemove={removeCollaborator}
        />
      )}
    </Box>
  );
}
