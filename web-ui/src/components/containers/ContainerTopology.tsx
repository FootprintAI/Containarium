'use client';

import { useState } from 'react';
import { Box, Typography, Button, CircularProgress, ToggleButton, ToggleButtonGroup } from '@mui/material';
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
  onRefresh,
}: ContainerTopologyProps) {
  const [viewMode, setViewMode] = useState<ViewMode>('grid');

  const handleViewModeChange = (_: React.MouseEvent<HTMLElement>, newMode: ViewMode | null) => {
    if (newMode !== null) {
      setViewMode(newMode);
    }
  };

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
      ) : viewMode === 'list' ? (
        <ContainerListView
          containers={containers}
          metricsMap={metricsMap}
          onDelete={onDeleteContainer}
          onStart={onStartContainer}
          onStop={onStopContainer}
          onTerminal={onTerminalContainer}
          onEditFirewall={onEditFirewall}
        />
      ) : (
        <Box
          sx={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))',
            gap: 2,
          }}
        >
          {containers.map((container) => (
            <ContainerNode
              key={container.name}
              container={container}
              metrics={metricsMap[container.name]}
              onDelete={onDeleteContainer}
              onStart={onStartContainer}
              onStop={onStopContainer}
              onTerminal={onTerminalContainer}
              onEditFirewall={onEditFirewall}
            />
          ))}
        </Box>
      )}
    </Box>
  );
}
