'use client';

import { useState, useMemo } from 'react';
import { Plus, RefreshCw, LayoutGrid, List, Search, Server as ServerIcon, Loader2 } from 'lucide-react';
import { Container, ContainerMetricsWithRate, SystemInfo, BackendInfo } from '@/src/types/container';
import ContainerNode from './ContainerNode';
import ContainerListView from './ContainerListView';
import CoreServicesSection from './CoreServicesSection';
import SystemResourcesCard from '../system/SystemResourcesCard';
import { CoreService } from '@/src/lib/api/client';
import { SecurityBadge } from '@/src/lib/hooks/useSecurity';

type ViewMode = 'grid' | 'list';

interface ContainerTopologyProps {
  containers: Container[];
  coreServices?: CoreService[];
  metricsMap: Record<string, ContainerMetricsWithRate>;
  systemInfo?: SystemInfo | null;
  isLoading: boolean;
  error?: Error | null;
  onCreateContainer: () => void;
  onDeleteContainer: (username: string) => void;
  onStartContainer: (username: string) => void;
  onStopContainer: (username: string) => void;
  onTerminalContainer?: (username: string) => void;
  onEditFirewall?: (username: string) => void;
  onEditLabels?: (username: string, labels: Record<string, string>) => void;
  onResize?: (username: string, currentResources: { cpu: string; memory: string; disk: string }) => void;
  onManageCollaborators?: (username: string) => void;
  onToggleAutoSleep?: (username: string, current: { enabled: boolean; threshold: number }) => void;
  onRefresh: () => void;
  backends?: BackendInfo[];
  onSelectBackend?: (backendId: string) => Promise<SystemInfo | null>;
  securityBadgesMap?: Record<string, SecurityBadge | null>;
  onSecurityClick?: (containerName: string) => void;
}

export default function ContainerTopology({
  containers, coreServices, metricsMap, systemInfo, isLoading, error,
  onCreateContainer, onDeleteContainer, onStartContainer, onStopContainer,
  onTerminalContainer, onEditFirewall, onEditLabels, onResize,
  onManageCollaborators, onToggleAutoSleep, onRefresh, backends, onSelectBackend,
  securityBadgesMap, onSecurityClick,
}: ContainerTopologyProps) {
  const [viewMode, setViewMode] = useState<ViewMode>('grid');
  const [groupByLabel, setGroupByLabel] = useState('');
  const [nodeFilter, setNodeFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  const availableNodes = useMemo(() => {
    const s = new Set<string>();
    containers.forEach(c => { if (c.backendId) s.add(c.backendId); });
    return Array.from(s).sort();
  }, [containers]);

  const filteredContainers = useMemo(() => {
    let r = containers;
    if (nodeFilter) r = r.filter(c => c.backendId === nodeFilter);
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      r = r.filter(c => c.name.toLowerCase().includes(q) || c.username.toLowerCase().includes(q) || (c.ipAddress && c.ipAddress.toLowerCase().includes(q)));
    }
    return r;
  }, [containers, nodeFilter, searchQuery]);

  const availableLabelKeys = useMemo(() => {
    const keys = new Set<string>();
    filteredContainers.forEach(c => { if (c.labels) Object.keys(c.labels).forEach(k => keys.add(k)); });
    return Array.from(keys).sort();
  }, [filteredContainers]);

  const groupedContainers = useMemo(() => {
    if (!groupByLabel) return { '': filteredContainers };
    const groups: Record<string, Container[]> = {};
    filteredContainers.forEach(c => {
      const v = c.labels?.[groupByLabel] || '(no label)';
      (groups[v] ||= []).push(c);
    });
    return Object.fromEntries(Object.keys(groups).sort().map(k => [k, groups[k]]));
  }, [filteredContainers, groupByLabel]);

  if (isLoading && containers.length === 0) {
    return (
      <div className="flex min-h-[300px] items-center justify-center">
        <Loader2 size={24} className="animate-spin text-[var(--text-secondary)]" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 py-16">
        <p className="text-sm font-medium text-[var(--c-red)]">Failed to load containers</p>
        <p className="text-xs text-[var(--text-muted)]">{error.message}</p>
        <button onClick={onRefresh} className="mt-2 rounded-md border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:bg-[var(--surface-2)] transition-colors">
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="p-6">
      {/* Toolbar */}
      <div className="mb-6 flex flex-wrap items-center gap-2">
        <h1 className="text-base font-semibold text-[var(--text)] mr-auto">
          Containers
          <span className="ml-2 text-sm font-normal text-[var(--text-muted)]">
            {filteredContainers.length}{filteredContainers.length !== containers.length ? ` / ${containers.length}` : ''}
          </span>
        </h1>

        {/* Search */}
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
          <input
            type="text"
            placeholder="Search..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-44 rounded-md border border-[var(--border-subtle)] bg-[var(--surface)] py-1.5 pl-7 pr-3 text-xs text-[var(--text)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent)] focus:outline-none"
          />
        </div>

        {/* Node filter */}
        {availableNodes.length > 1 && (
          <div className="relative">
            <ServerIcon size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
            <select
              value={nodeFilter}
              onChange={e => setNodeFilter(e.target.value)}
              className="w-44 appearance-none rounded-md border border-[var(--border-subtle)] bg-[var(--surface)] py-1.5 pl-7 pr-3 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
            >
              <option value="">All nodes</option>
              {availableNodes.map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          </div>
        )}

        {/* Group by */}
        {availableLabelKeys.length > 0 && (
          <select
            value={groupByLabel}
            onChange={e => setGroupByLabel(e.target.value)}
            className="appearance-none rounded-md border border-[var(--border-subtle)] bg-[var(--surface)] px-3 py-1.5 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
          >
            <option value="">Group by…</option>
            {availableLabelKeys.map(k => <option key={k} value={k}>{k}</option>)}
          </select>
        )}

        {/* View mode toggle */}
        <div className="flex rounded-md border border-[var(--border-subtle)] overflow-hidden">
          {(['grid', 'list'] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setViewMode(mode)}
              className={`flex items-center gap-1 px-2.5 py-1.5 text-xs transition-colors ${viewMode === mode ? 'bg-[var(--accent)] text-white' : 'bg-[var(--surface)] text-[var(--text-secondary)] hover:bg-[var(--surface-2)]'}`}
            >
              {mode === 'grid' ? <LayoutGrid size={13} /> : <List size={13} />}
            </button>
          ))}
        </div>

        <button
          onClick={onRefresh}
          disabled={isLoading}
          className="flex items-center gap-1.5 rounded-md border border-[var(--border-subtle)] bg-[var(--surface)] px-3 py-1.5 text-xs text-[var(--text-secondary)] transition-colors hover:bg-[var(--surface-2)] disabled:opacity-50"
        >
          <RefreshCw size={12} className={isLoading ? 'animate-spin' : ''} />
          Refresh
        </button>

        <button
          onClick={onCreateContainer}
          className="flex items-center gap-1.5 rounded-md bg-[var(--accent)] px-3 py-1.5 text-xs font-medium text-white hover:bg-[var(--accent-hover)] transition-colors"
        >
          <Plus size={13} />
          Create Container
        </button>
      </div>

      {/* System Resources */}
      <SystemResourcesCard systemInfo={systemInfo || null} backends={backends} onSelectBackend={onSelectBackend} />

      {/* Core Infrastructure */}
      {coreServices && coreServices.length > 0 && (
        <CoreServicesSection services={coreServices} />
      )}

      {/* Empty state */}
      {filteredContainers.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-2 py-16">
          <p className="text-sm text-[var(--text-secondary)]">
            {containers.length === 0 ? 'No containers found' : 'No containers match the current filters'}
          </p>
          {containers.length === 0 ? (
            <button onClick={onCreateContainer} className="mt-2 flex items-center gap-1.5 rounded-md bg-[var(--accent)] px-3 py-1.5 text-xs font-medium text-white hover:bg-[var(--accent-hover)] transition-colors">
              <Plus size={13} />
              Create your first container
            </button>
          ) : (
            <button onClick={() => { setNodeFilter(''); setSearchQuery(''); }} className="mt-2 rounded-md border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:bg-[var(--surface-2)] transition-colors">
              Clear filters
            </button>
          )}
        </div>
      ) : (
        <div className="flex flex-col gap-6">
          {Object.entries(groupedContainers).map(([groupName, groupContainers]) => (
            <div key={groupName}>
              {groupByLabel && (
                <div className="mb-3 flex items-center gap-2">
                  <span className="rounded-full border border-blue-500/30 bg-blue-500/10 px-2.5 py-0.5 text-xs text-[var(--c-blue)]">
                    {groupByLabel}: {groupName}
                  </span>
                  <span className="text-xs text-[var(--text-muted)]">{groupContainers.length} container{groupContainers.length !== 1 ? 's' : ''}</span>
                </div>
              )}
              {viewMode === 'list' ? (
                <ContainerListView
                  containers={groupContainers}
                  metricsMap={metricsMap}
                  securityBadgesMap={securityBadgesMap}
                  onDelete={onDeleteContainer}
                  onStart={onStartContainer}
                  onStop={onStopContainer}
                  onTerminal={onTerminalContainer}
                  onEditFirewall={onEditFirewall}
                  onEditLabels={onEditLabels}
                  onResize={onResize}
                  onManageCollaborators={onManageCollaborators}
                  onToggleAutoSleep={onToggleAutoSleep}
                  onSecurityClick={onSecurityClick}
                />
              ) : (
                <div className="grid gap-4" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))' }}>
                  {groupContainers.map(container => (
                    <ContainerNode
                      key={container.name}
                      container={container}
                      metrics={metricsMap[container.name]}
                      securityBadge={securityBadgesMap?.[container.name]}
                      onDelete={onDeleteContainer}
                      onStart={onStartContainer}
                      onStop={onStopContainer}
                      onTerminal={onTerminalContainer}
                      onEditFirewall={onEditFirewall}
                      onEditLabels={onEditLabels ? (u) => onEditLabels(u, container.labels || {}) : undefined}
                      onResize={onResize ? (u) => onResize(u, { cpu: container.cpu, memory: container.memory, disk: container.disk }) : undefined}
                      onToggleAutoSleep={onToggleAutoSleep}
                      onSecurityClick={onSecurityClick ? () => onSecurityClick(container.name) : undefined}
                    />
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
