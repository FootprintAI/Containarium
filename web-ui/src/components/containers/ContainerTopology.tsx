'use client';

import { useState, useMemo } from 'react';
import { Box, Typography, Button, CircularProgress, ToggleButton, ToggleButtonGroup, FormControl, InputLabel, Select, MenuItem, Chip, TextField, InputAdornment } from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import RefreshIcon from '@mui/icons-material/Refresh';
import GridViewIcon from '@mui/icons-material/GridView';
import ViewListIcon from '@mui/icons-material/ViewList';
import SearchIcon from '@mui/icons-material/Search';
import DnsIcon from '@mui/icons-material/Dns';
import { Container, ContainerMetricsWithRate, SystemInfo, BackendInfo } from '@/src/types/container';
import ContainerNode from './ContainerNode';
import ContainerListView from './ContainerListView';
import CoreServicesSection from './CoreServicesSection';
import SystemResourcesCard from '../system/SystemResourcesCard';
import { CoreService } from '@/src/lib/api/client';

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
  onRefresh: () => void;
  backends?: BackendInfo[];
  onSelectBackend?: (backendId: string) => Promise<SystemInfo | null>;
}

export default function ContainerTopology({
  containers,
  coreServices,
  metricsMap,
  systemInfo,
  isLoading,
  error,
  onCreateContainer,
  onDeleteContainer,
  onStartContainer,
  onStopContainer,
  onTerminalContainer,
  onEditFirewall,
  onEditLabels,
  onResize,
  onManageCollaborators,
  onRefresh,
  backends,
  onSelectBackend,
}: ContainerTopologyProps) {
  const [viewMode, setViewMode] = useState<ViewMode>('grid');
  const [groupByLabel, setGroupByLabel] = useState<string>('');
  const [nodeFilter, setNodeFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const handleViewModeChange = (_: React.MouseEvent<HTMLElement>, newMode: ViewMode | null) => {
    if (newMode !== null) {
      setViewMode(newMode);
    }
  };

  // Extract unique backend/node IDs
  const availableNodes = useMemo(() => {
    const nodes = new Set<string>();
    containers.forEach(c => {
      if (c.backendId) nodes.add(c.backendId);
    });
    return Array.from(nodes).sort();
  }, [containers]);

  // Filter containers by node and search query
  const filteredContainers = useMemo(() => {
    let result = containers;
    if (nodeFilter) {
      result = result.filter(c => c.backendId === nodeFilter);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(c =>
        c.name.toLowerCase().includes(q) ||
        c.username.toLowerCase().includes(q) ||
        (c.ipAddress && c.ipAddress.toLowerCase().includes(q))
      );
    }
    return result;
  }, [containers, nodeFilter, searchQuery]);

  // Extract all unique label keys from containers
  const availableLabelKeys = useMemo(() => {
    const keys = new Set<string>();
    filteredContainers.forEach(c => {
      if (c.labels) {
        Object.keys(c.labels).forEach(k => keys.add(k));
      }
    });
    return Array.from(keys).sort();
  }, [filteredContainers]);

  // Group containers by selected label
  const groupedContainers = useMemo(() => {
    if (!groupByLabel) {
      return { '': filteredContainers };
    }
    const groups: Record<string, Container[]> = {};
    filteredContainers.forEach(c => {
      const labelValue = c.labels?.[groupByLabel] || '(no label)';
      if (!groups[labelValue]) {
        groups[labelValue] = [];
      }
      groups[labelValue].push(c);
    });
    // Sort group keys
    const sortedGroups: Record<string, Container[]> = {};
    Object.keys(groups).sort().forEach(key => {
      sortedGroups[key] = groups[key];
    });
    return sortedGroups;
  }, [filteredContainers, groupByLabel]);

  if (isLoading && containers.length === 0) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 300 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography color="error" gutterBottom>
          Failed to load containers
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {error.message}
        </Typography>
        <Button onClick={onRefresh} sx={{ mt: 2 }}>
          Retry
        </Button>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5">
          Containers ({filteredContainers.length}{filteredContainers.length !== containers.length ? ` / ${containers.length}` : ''})
        </Typography>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
          <TextField
            size="small"
            placeholder="Search..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            sx={{ width: 180 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon fontSize="small" color="action" />
                </InputAdornment>
              ),
            }}
          />
          {availableNodes.length > 1 && (
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel id="node-filter-label">Node</InputLabel>
              <Select
                labelId="node-filter-label"
                value={nodeFilter}
                label="Node"
                onChange={(e) => setNodeFilter(e.target.value)}
                startAdornment={
                  <InputAdornment position="start">
                    <DnsIcon fontSize="small" color="action" />
                  </InputAdornment>
                }
              >
                <MenuItem value="">
                  <em>All nodes</em>
                </MenuItem>
                {availableNodes.map(node => (
                  <MenuItem key={node} value={node}>{node}</MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
          {availableLabelKeys.length > 0 && (
            <FormControl size="small" sx={{ minWidth: 140 }}>
              <InputLabel id="group-by-label">Group by</InputLabel>
              <Select
                labelId="group-by-label"
                value={groupByLabel}
                label="Group by"
                onChange={(e) => setGroupByLabel(e.target.value)}
              >
                <MenuItem value="">
                  <em>None</em>
                </MenuItem>
                {availableLabelKeys.map(key => (
                  <MenuItem key={key} value={key}>{key}</MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
          <ToggleButtonGroup
            value={viewMode}
            exclusive
            onChange={handleViewModeChange}
            size="small"
          >
            <ToggleButton value="grid" aria-label="grid view">
              <GridViewIcon fontSize="small" />
            </ToggleButton>
            <ToggleButton value="list" aria-label="list view">
              <ViewListIcon fontSize="small" />
            </ToggleButton>
          </ToggleButtonGroup>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={onRefresh}
            disabled={isLoading}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={onCreateContainer}
          >
            Create Container
          </Button>
        </Box>
      </Box>

      {/* System Resources */}
      <SystemResourcesCard
        systemInfo={systemInfo || null}
        backends={backends}
        onSelectBackend={onSelectBackend}
      />

      {/* Core Infrastructure Services */}
      {coreServices && coreServices.length > 0 && (
        <CoreServicesSection services={coreServices} />
      )}

      {filteredContainers.length === 0 ? (
        <Box sx={{ textAlign: 'center', py: 6 }}>
          <Typography color="text.secondary" gutterBottom>
            {containers.length === 0 ? 'No containers found' : 'No containers match the current filters'}
          </Typography>
          {containers.length === 0 ? (
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={onCreateContainer}
              sx={{ mt: 2 }}
            >
              Create your first container
            </Button>
          ) : (
            <Button
              variant="outlined"
              onClick={() => { setNodeFilter(''); setSearchQuery(''); }}
              sx={{ mt: 2 }}
            >
              Clear filters
            </Button>
          )}
        </Box>
      ) : (
        <>
          {Object.entries(groupedContainers).map(([groupName, groupContainers]) => (
            <Box key={groupName} sx={{ mb: groupByLabel ? 4 : 0 }}>
              {groupByLabel && (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2, mt: 2 }}>
                  <Chip
                    label={`${groupByLabel}: ${groupName}`}
                    color={groupName === '(no label)' ? 'default' : 'primary'}
                    variant="outlined"
                  />
                  <Typography variant="body2" color="text.secondary">
                    ({groupContainers.length} container{groupContainers.length !== 1 ? 's' : ''})
                  </Typography>
                </Box>
              )}
              {viewMode === 'list' ? (
                <ContainerListView
                  containers={groupContainers}
                  metricsMap={metricsMap}
                  onDelete={onDeleteContainer}
                  onStart={onStartContainer}
                  onStop={onStopContainer}
                  onTerminal={onTerminalContainer}
                  onEditFirewall={onEditFirewall}
                  onEditLabels={onEditLabels}
                  onResize={onResize}
                  onManageCollaborators={onManageCollaborators}
                />
              ) : (
                <Box
                  sx={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
                    gap: 2,
                  }}
                >
                  {groupContainers.map((container) => (
                    <ContainerNode
                      key={container.name}
                      container={container}
                      metrics={metricsMap[container.name]}
                      onDelete={onDeleteContainer}
                      onStart={onStartContainer}
                      onStop={onStopContainer}
                      onTerminal={onTerminalContainer}
                      onEditFirewall={onEditFirewall}
                      onEditLabels={onEditLabels ? (username: string) => onEditLabels(username, container.labels || {}) : undefined}
                      onResize={onResize ? (username: string) => onResize(username, { cpu: container.cpu, memory: container.memory, disk: container.disk }) : undefined}
                    />
                  ))}
                </Box>
              )}
            </Box>
          ))}
        </>
      )}
    </Box>
  );
}
