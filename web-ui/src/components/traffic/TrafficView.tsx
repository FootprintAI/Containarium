'use client';

import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Tooltip,
  Stack,
  Chip,
  Alert,
  Divider,
  Paper,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import PauseIcon from '@mui/icons-material/Pause';
import { Server } from '@/src/types/server';
import { Container } from '@/src/types/container';
import { useTraffic } from '@/src/lib/hooks/useTraffic';
import { formatBytes } from '@/src/types/traffic';
import ConnectionsTable from './ConnectionsTable';

interface TrafficViewProps {
  server: Server;
  containers: Container[];
}

export default function TrafficView({ server, containers }: TrafficViewProps) {
  const [selectedContainer, setSelectedContainer] = useState<string>('');

  const { connections, summary, isLoading, error, autoRefresh, refresh, toggleAutoRefresh, eventStatus } =
    useTraffic(server, selectedContainer || null);

  // Get only running containers
  const runningContainers = containers.filter((c) => c.state === 'Running');

  return (
    <Box sx={{ p: 2 }}>
      {/* Header with container selector */}
      <Card variant="outlined" sx={{ mb: 2 }}>
        <CardContent>
          <Stack direction="row" spacing={2} alignItems="center" justifyContent="space-between">
            <Stack direction="row" spacing={2} alignItems="center">
              <Typography variant="h6">Traffic Monitor</Typography>
              <FormControl size="small" sx={{ minWidth: 250 }}>
                <InputLabel>Select Container</InputLabel>
                <Select
                  value={selectedContainer}
                  label="Select Container"
                  onChange={(e) => setSelectedContainer(e.target.value)}
                >
                  <MenuItem value="">
                    <em>Select a container</em>
                  </MenuItem>
                  {runningContainers.map((container) => (
                    <MenuItem key={container.name} value={container.name}>
                      {container.name} ({container.ipAddress})
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Stack>

            <Stack direction="row" spacing={1} alignItems="center">
              <Chip
                size="small"
                label={eventStatus === 'connected' ? 'Live' : eventStatus}
                color={eventStatus === 'connected' ? 'success' : 'default'}
                variant="outlined"
              />
              <Tooltip title={autoRefresh ? 'Pause auto-refresh' : 'Enable auto-refresh'}>
                <IconButton onClick={toggleAutoRefresh} size="small">
                  {autoRefresh ? <PauseIcon /> : <PlayArrowIcon />}
                </IconButton>
              </Tooltip>
              <Tooltip title="Refresh now">
                <IconButton onClick={refresh} size="small" disabled={!selectedContainer}>
                  <RefreshIcon />
                </IconButton>
              </Tooltip>
            </Stack>
          </Stack>
        </CardContent>
      </Card>

      {/* No container selected */}
      {!selectedContainer && (
        <Alert severity="info">Select a running container to view its network connections.</Alert>
      )}

      {/* Error state */}
      {error && selectedContainer && (
        <Alert severity="error" sx={{ mb: 2 }}>
          Failed to load traffic data: {error.message || 'Unknown error'}
        </Alert>
      )}

      {/* Traffic content */}
      {selectedContainer && (
        <>
          {/* Summary stats */}
          {summary && (
            <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
              <Stack direction="row" spacing={4} divider={<Divider orientation="vertical" flexItem />}>
                <Box>
                  <Typography variant="caption" color="text.secondary">
                    Active Connections
                  </Typography>
                  <Typography variant="h5">{summary.activeConnections}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" color="text.secondary">
                    TCP
                  </Typography>
                  <Typography variant="h5">{summary.tcpConnections}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" color="text.secondary">
                    UDP
                  </Typography>
                  <Typography variant="h5">{summary.udpConnections}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" color="text.secondary">
                    Total Sent
                  </Typography>
                  <Typography variant="h5">{formatBytes(summary.totalBytesSent)}</Typography>
                </Box>
                <Box>
                  <Typography variant="caption" color="text.secondary">
                    Total Received
                  </Typography>
                  <Typography variant="h5">{formatBytes(summary.totalBytesReceived)}</Typography>
                </Box>
              </Stack>
            </Paper>
          )}

          {/* Connections table */}
          <Card variant="outlined">
            <CardContent>
              <Typography variant="subtitle1" gutterBottom>
                Active Connections ({connections.length})
              </Typography>
              <ConnectionsTable connections={connections} isLoading={isLoading} />
            </CardContent>
          </Card>

          {/* Top destinations */}
          {summary && summary.topDestinations && summary.topDestinations.length > 0 && (
            <Card variant="outlined" sx={{ mt: 2 }}>
              <CardContent>
                <Typography variant="subtitle1" gutterBottom>
                  Top Destinations
                </Typography>
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  {summary.topDestinations.slice(0, 10).map((dest) => (
                    <Chip
                      key={dest.destIp}
                      label={`${dest.destIp} (${dest.connectionCount} conn, ${formatBytes(dest.bytesTotal)})`}
                      variant="outlined"
                      size="small"
                    />
                  ))}
                </Stack>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </Box>
  );
}
