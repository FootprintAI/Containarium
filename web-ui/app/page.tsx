'use client';

import { useState, useMemo, useEffect, useCallback } from 'react';
import dynamic from 'next/dynamic';
import { usePathname } from 'next/navigation';
import {
  Server as ServerIcon, LayoutGrid, Network, Activity, BarChart2,
  Shield, ClipboardList, Bell, Loader2, RefreshCw, Bot
} from 'lucide-react';
import AppBar from '@/src/components/layout/AppBar';
import ServerTabs from '@/src/components/layout/ServerTabs';
import AddServerDialog from '@/src/components/servers/AddServerDialog';
import ContainerTopology from '@/src/components/containers/ContainerTopology';
import CreateContainerDialog from '@/src/components/containers/CreateContainerDialog';
import DeleteConfirmDialog from '@/src/components/containers/DeleteConfirmDialog';
import LabelEditorDialog from '@/src/components/containers/LabelEditorDialog';
import ResizeContainerDialog from '@/src/components/containers/ResizeContainerDialog';
import AutoSleepDialog from '@/src/components/containers/AutoSleepDialog';
import CollaboratorsDialog from '@/src/components/containers/CollaboratorsDialog';
import AppsView from '@/src/components/apps/AppsView';
import NetworkTopologyView from '@/src/components/network/NetworkTopologyView';
import FirewallEditor from '@/src/components/network/FirewallEditor';
import TrafficView from '@/src/components/traffic/TrafficView';
import MonitoringView from '@/src/components/monitoring/MonitoringView';
import SecurityView from '@/src/components/security/SecurityView';
import AuditView from '@/src/components/audit/AuditView';
import AlertsView from '@/src/components/alerts/AlertsView';
import VersionsView from '@/src/components/versions/VersionsView';
import WorkspaceView from '@/src/components/workspace/WorkspaceView';
import { useServers } from '@/src/lib/hooks/useServers';
import { useContainers, CreateContainerProgress } from '@/src/lib/hooks/useContainers';
import { useMetrics } from '@/src/lib/hooks/useMetrics';
import { useApps } from '@/src/lib/hooks/useApps';
import { useRoutes, usePassthroughRoutes, useNetworkTopology, useContainerACL, useACLPresets, useDNSRecords } from '@/src/lib/hooks/useNetwork';
import { useCollaborators } from '@/src/lib/hooks/useCollaborators';
import { CreateContainerRequest, ContainerMetricsWithRate } from '@/src/types/container';
import { Server } from '@/src/types/server';
import { ACLPreset } from '@/src/types/app';

const TerminalDialog = dynamic(
  () => import('@/src/components/containers/TerminalDialog'),
  { ssr: false }
);

const TAB_PATHS = ['/containers/', '/apps/', '/network/', '/traffic/', '/monitoring/', '/security/', '/audit/', '/alerts/', '/versions/', '/workspace/'] as const;
const TAB_INDICES: Record<string, number> = {
  '/': 0,
  '/containers/': 0,
  '/apps/': 1,
  '/network/': 2,
  '/traffic/': 3,
  '/monitoring/': 4,
  '/security/': 5,
  '/audit/': 6,
  '/alerts/': 7,
  '/versions/': 8,
  '/workspace/': 9,
};

const TABS = [
  { label: 'Containers', icon: ServerIcon },
  { label: 'Apps',       icon: LayoutGrid },
  { label: 'Network',    icon: Network },
  { label: 'Traffic',    icon: Activity },
  { label: 'Monitoring', icon: BarChart2 },
  { label: 'Security',   icon: Shield },
  { label: 'Audit',      icon: ClipboardList },
  { label: 'Alerts',     icon: Bell },
  { label: 'Versions',   icon: RefreshCw },
  { label: 'Workspace',  icon: Bot },
] as const;

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

  const currentPath = (pathname || '/').replace(/\/?$/, '/');
  const tabFromPath = TAB_INDICES[currentPath] ?? 0;
  const [viewTab, setViewTabState] = useState(tabFromPath);

  useEffect(() => {
    const onPopState = () => {
      const path = window.location.pathname.replace(/^\/webui/, '').replace(/\/?$/, '/');
      setViewTabState(TAB_INDICES[path] ?? 0);
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  const setViewTab = useCallback((newTab: number) => {
    setViewTabState(newTab);
    const path = '/webui' + (TAB_PATHS[newTab] || '/containers/');
    window.history.pushState(null, '', path);
  }, []);

  const {
    containers,
    coreServices,
    systemInfo,
    backends,
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
    toggleAutoSleep,
    getSystemInfoForBackend,
    refresh: refreshContainers,
  } = useContainers(activeServer);

  const hasRunningContainers = containers.some(c => c.state === 'Running');
  const { metrics } = useMetrics(activeServer, hasRunningContainers);

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

  const [includeStopped, setIncludeStopped] = useState(false);
  const { routes, isLoading: routesLoading, error: routesError, addRoute, deleteRoute, updateRoute, refresh: refreshRoutes } = useRoutes(activeServer);
  const { routes: passthroughRoutes, isLoading: passthroughLoading, addPassthroughRoute, deletePassthroughRoute, updatePassthroughRoute, refresh: refreshPassthrough } = usePassthroughRoutes(activeServer);
  const { topology, isLoading: topologyLoading, error: topologyError, refresh: refreshTopology } = useNetworkTopology(activeServer, includeStopped);
  const { presets, isLoading: presetsLoading } = useACLPresets(activeServer);
  const { records: dnsRecords, baseDomain, refresh: refreshDNS } = useDNSRecords(activeServer);

  const [firewallEditorOpen, setFirewallEditorOpen] = useState(false);
  const [selectedContainer, setSelectedContainer] = useState<string | null>(null);
  const { acl, isLoading: aclLoading, updateACL } = useContainerACL(activeServer, selectedContainer || '');

  const [collaboratorContainer, setCollaboratorContainer] = useState<string | null>(null);
  const { collaborators, isLoading: collaboratorsLoading, addCollaborator, removeCollaborator } = useCollaborators(activeServer, collaboratorContainer);

  const metricsMap = useMemo(() => {
    const map: Record<string, ContainerMetricsWithRate> = {};
    for (const m of metrics) map[m.name] = m;
    return map;
  }, [metrics]);

  const [serverDialogOpen, setServerDialogOpen] = useState(false);
  const [editingServer, setEditingServer] = useState<Server | null>(null);
  const [createContainerOpen, setCreateContainerOpen] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<{ open: boolean; containerName: string }>({ open: false, containerName: '' });
  const [terminalOpen, setTerminalOpen] = useState(false);
  const [terminalUsername, setTerminalUsername] = useState('');
  const [labelEditorOpen, setLabelEditorOpen] = useState(false);
  const [labelEditorContainer, setLabelEditorContainer] = useState<{ username: string; labels: Record<string, string> } | null>(null);
  const [resizeDialogOpen, setResizeDialogOpen] = useState(false);
  const [resizeTarget, setResizeTarget] = useState<{ username: string; cpu: string; memory: string; disk: string } | null>(null);
  const [autoSleepTarget, setAutoSleepTarget] = useState<{ username: string; enabled: boolean; threshold: number } | null>(null);

  const handleEditServer = (serverId: string) => {
    const server = servers.find(s => s.id === serverId);
    if (server) { setEditingServer(server); setServerDialogOpen(true); }
  };

  const handleConfirmDelete = async () => {
    await deleteContainer(deleteConfirm.containerName, true);
  };

  const handleCloseTerminal = () => { setTerminalOpen(false); setTerminalUsername(''); };

  const handleEditLabels = (username: string, labels: Record<string, string>) => {
    setLabelEditorContainer({ username, labels });
    setLabelEditorOpen(true);
  };

  const handleOpenResize = (username: string, currentResources: { cpu: string; memory: string; disk: string }) => {
    setResizeTarget({ username, ...currentResources });
    setResizeDialogOpen(true);
  };

  const handleResize = async (resources: { cpu?: string; memory?: string; disk?: string }) => {
    if (!resizeTarget) return;
    await resizeContainer(resizeTarget.username, resources);
  };

  const handleOpenAutoSleep = (username: string, current: { enabled: boolean; threshold: number }) => {
    setAutoSleepTarget({ username, ...current });
  };

  const handleAutoSleepSave = async (enabled: boolean, idleThresholdMinutes: number) => {
    if (!autoSleepTarget) return;
    await toggleAutoSleep(autoSleepTarget.username, enabled, idleThresholdMinutes);
  };

  const handleEditContainerFirewall = (username: string) => {
    setSelectedContainer(username);
    setFirewallEditorOpen(true);
  };

  const handleRefreshNetwork = () => {
    refreshRoutes();
    refreshTopology();
    refreshDNS();
  };

  if (serversLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-[var(--background)]">
        <Loader2 size={24} className="animate-spin text-[var(--text-secondary)]" />
      </div>
    );
  }

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-[var(--background)]">
      <AppBar onAddServer={() => setServerDialogOpen(true)} />

      <ServerTabs
        servers={servers}
        activeServerId={activeServerId}
        onServerChange={setActiveServerId}
        onRemoveServer={removeServer}
        onEditServer={handleEditServer}
      />

      {servers.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-2">
          <p className="text-sm font-medium text-[var(--text)]">No servers added</p>
          <p className="text-xs text-[var(--text-secondary)]">Click &ldquo;Add Server&rdquo; to connect to a Containarium server</p>
        </div>
      ) : activeServer ? (
        <>
          {/* View tab bar */}
          <div className="flex items-end gap-0 overflow-x-auto border-b border-[var(--border-subtle)] bg-[var(--surface)] px-4 shrink-0">
            {TABS.map(({ label, icon: Icon }, i) => (
              <button
                key={label}
                onClick={() => setViewTab(i)}
                className={[
                  'flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium transition-colors border-b-2 -mb-px',
                  viewTab === i
                    ? 'border-[var(--accent)] text-[var(--accent)]'
                    : 'border-transparent text-[var(--text-secondary)] hover:text-[var(--text)]',
                ].join(' ')}
              >
                <Icon size={13} />
                {label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="flex-1 overflow-auto">
            {viewTab === 0 && (
              <ContainerTopology
                containers={containers}
                coreServices={coreServices}
                metricsMap={metricsMap}
                systemInfo={systemInfo}
                isLoading={containersLoading}
                error={containersError as Error | null}
                onCreateContainer={() => setCreateContainerOpen(true)}
                onDeleteContainer={(u) => setDeleteConfirm({ open: true, containerName: u })}
                onStartContainer={startContainer}
                onStopContainer={stopContainer}
                onTerminalContainer={(u) => { setTerminalUsername(u); setTerminalOpen(true); }}
                onEditFirewall={handleEditContainerFirewall}
                onEditLabels={handleEditLabels}
                onResize={handleOpenResize}
                onManageCollaborators={(u) => setCollaboratorContainer(u)}
                onToggleAutoSleep={handleOpenAutoSleep}
                onRefresh={refreshContainers}
                backends={backends}
                onSelectBackend={getSystemInfoForBackend}
              />
            )}
            {viewTab === 1 && (
              <AppsView
                apps={apps}
                isLoading={appsLoading}
                error={appsError as Error | null}
                onStopApp={async (u, a) => { await stopApp(u, a); }}
                onStartApp={async (u, a) => { await startApp(u, a); }}
                onRestartApp={async (u, a) => { await restartApp(u, a); }}
                onDeleteApp={async (u, a) => { await deleteApp(u, a, false); }}
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
                onAddRoute={async (d, ip, p, proto) => { await addRoute(d, ip, p, proto); }}
                onDeleteRoute={async (d) => { await deleteRoute(d); }}
                onToggleRoute={async (d, en) => { await updateRoute(d, { active: en }); }}
                onAddPassthroughRoute={async (ep, ip, p, proto, cn) => { await addPassthroughRoute(ep, ip, p, proto, cn); }}
                onDeletePassthroughRoute={async (ep, proto) => { await deletePassthroughRoute(ep, proto); }}
                onTogglePassthroughRoute={async (ep, proto, en) => { await updatePassthroughRoute(ep, proto, { active: en }); }}
                onRefresh={() => { handleRefreshNetwork(); refreshPassthrough(); }}
              />
            )}
            {viewTab === 3 && <TrafficView server={activeServer} containers={containers} proxyRoutes={routes} passthroughRoutes={passthroughRoutes} />}
            {viewTab === 4 && <MonitoringView server={activeServer} />}
            {viewTab === 5 && <SecurityView server={activeServer} />}
            {viewTab === 6 && <AuditView server={activeServer} />}
            {viewTab === 7 && <AlertsView server={activeServer} />}
            {viewTab === 8 && <VersionsView server={activeServer} />}
            {viewTab === 9 && <WorkspaceView routes={routes} />}
          </div>
        </>
      ) : (
        <div className="flex flex-1 items-center justify-center">
          <p className="text-sm text-[var(--text-secondary)]">Select a server to view containers</p>
        </div>
      )}

      {/* Dialogs */}
      <AddServerDialog
        open={serverDialogOpen}
        onClose={() => { setServerDialogOpen(false); setEditingServer(null); }}
        onAdd={async (name, endpoint, token) => { await addServer(name, endpoint, token); }}
        onUpdate={async (id, name, endpoint, token) => { await updateServer(id, name, endpoint, token); }}
        editServer={editingServer}
      />

      <CreateContainerDialog
        open={createContainerOpen}
        onClose={() => setCreateContainerOpen(false)}
        onSubmit={async (req: CreateContainerRequest, onProgress?: (p: CreateContainerProgress) => void) => createContainer(req, onProgress)}
        networkCidr={systemInfo?.networkCidr}
        backends={backends}
        server={activeServer}
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

      <FirewallEditor
        open={firewallEditorOpen}
        onClose={() => { setFirewallEditorOpen(false); setSelectedContainer(null); }}
        acl={acl || null}
        presets={presets}
        isLoading={aclLoading || presetsLoading}
        appName={selectedContainer ? `${selectedContainer}-container` : ''}
        username={selectedContainer || ''}
        onSave={async (preset: ACLPreset) => { if (selectedContainer) await updateACL(preset); }}
      />

      {labelEditorContainer && (
        <LabelEditorDialog
          open={labelEditorOpen}
          onClose={() => { setLabelEditorOpen(false); setLabelEditorContainer(null); }}
          containerName={`${labelEditorContainer.username}-container`}
          username={labelEditorContainer.username}
          currentLabels={labelEditorContainer.labels}
          onSave={async (labels) => { await setLabels(labelEditorContainer.username, labels); }}
          onRemove={async (key) => { await removeLabel(labelEditorContainer.username, key); }}
        />
      )}

      {autoSleepTarget && (
        <AutoSleepDialog
          open={!!autoSleepTarget}
          onClose={() => setAutoSleepTarget(null)}
          username={autoSleepTarget.username}
          initialEnabled={autoSleepTarget.enabled}
          initialIdleThresholdMinutes={autoSleepTarget.threshold}
          onSave={handleAutoSleepSave}
        />
      )}

      {resizeTarget && (
        <ResizeContainerDialog
          open={resizeDialogOpen}
          onClose={() => { setResizeDialogOpen(false); setResizeTarget(null); }}
          containerName={`${resizeTarget.username}-container`}
          username={resizeTarget.username}
          currentCpu={resizeTarget.cpu}
          currentMemory={resizeTarget.memory}
          currentDisk={resizeTarget.disk}
          memoryUsageBytes={metricsMap[`${resizeTarget.username}-container`]?.memoryUsageBytes}
          diskUsageBytes={metricsMap[`${resizeTarget.username}-container`]?.diskUsageBytes}
          onResize={handleResize}
          onCleanupDisk={async () => { if (!resizeTarget) throw new Error('No container selected'); return cleanupDisk(resizeTarget.username); }}
        />
      )}

      {collaboratorContainer && (
        <CollaboratorsDialog
          open={!!collaboratorContainer}
          onClose={() => setCollaboratorContainer(null)}
          ownerUsername={collaboratorContainer}
          collaborators={collaborators}
          isLoading={collaboratorsLoading}
          onAdd={async (req) => { const result = await addCollaborator(req); return { sshCommand: result.sshCommand }; }}
          onRemove={removeCollaborator}
        />
      )}
    </div>
  );
}
