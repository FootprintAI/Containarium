'use client';

import { useState, useMemo } from 'react';
import { Box, Typography, Button, CircularProgress, ToggleButton, ToggleButtonGroup, FormControl, InputLabel, Select, MenuItem, Chip } from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import RefreshIcon from '@mui/icons-material/Refresh';
import GridViewIcon from '@mui/icons-material/GridView';
import ViewListIcon from '@mui/icons-material/ViewList';
import { Container, ContainerMetricsWithRate, SystemInfo } from '@/src/types/container';
import ContainerNode from './ContainerNode';
import ContainerListView from './ContainerListView';
import SystemResourcesCard from '../system/SystemResourcesCard';

type ViewMode = 'grid' | 'list';

interface ContainerTopologyProps {
  containers: Container[];
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
  onRefresh: () => void;
}

export default function ContainerTopology({
  containers,
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
  onRefresh,
}: ContainerTopologyProps) {
  const [viewMode, setViewMode] = useState<ViewMode>('grid');
  const [groupByLabel, setGroupByLabel] = useState<string>('');

  const handleViewModeChange = (_: React.MouseEvent<HTMLElement>, newMode: ViewMode | null) => {
    if (newMode !== null) {
      setViewMode(newMode);
    }
  };

  // Extract all unique label keys from containers
  const availableLabelKeys = useMemo(() => {
    const keys = new Set<string>();
    containers.forEach(c => {
      if (c.labels) {
        Object.keys(c.labels).forEach(k => keys.add(k));
      }
    });
    return Array.from(keys).sort();
  }, [containers]);

  // Group containers by selected label
  const groupedContainers = useMemo(() => {
    if (!groupByLabel) {
      return { '': containers };
    }
    const groups: Record<string, Container[]> = {};
    containers.forEach(c => {
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
  }, [containers, groupByLabel]);

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
          Containers ({containers.length})
        </Typography>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
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
      <SystemResourcesCard systemInfo={systemInfo || null} />

      {containers.length === 0 ? (
        <Box sx={{ textAlign: 'center', py: 6 }}>
          <Typography color="text.secondary" gutterBottom>
            No containers found
          </Typography>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={onCreateContainer}
            sx={{ mt: 2 }}
          >
            Create your first container
          </Button>
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
