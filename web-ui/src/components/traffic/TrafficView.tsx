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
  Tabs,
  Tab,
  TextField,
  LinearProgress,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import PauseIcon from '@mui/icons-material/Pause';
import PublicIcon from '@mui/icons-material/Public';
import CableIcon from '@mui/icons-material/Cable';
import { Server } from '@/src/types/server';
import { Container } from '@/src/types/container';
import { ProxyRoute, PassthroughRoute, getRouteProtocolName, isGRPCRoute } from '@/src/types/app';
import { useTraffic } from '@/src/lib/hooks/useTraffic';
import { formatBytes } from '@/src/types/traffic';
import ConnectionsTable from './ConnectionsTable';

/**
 * Traffic stats for a route
 */
export interface RouteTrafficStats {
  routeId: string;
  requestsPerMin: number;
  bytesPerMin: number;
}

// Helper to format traffic numbers
function formatTraffic(value: number): string {
  if (value >= 1000000) return `${(value / 1000000).toFixed(1)}M`;
  if (value >= 1000) return `${(value / 1000).toFixed(1)}K`;
  return value.toString();
}

interface TrafficViewProps {
  server: Server;
  containers: Container[];
  proxyRoutes?: ProxyRoute[];
  passthroughRoutes?: PassthroughRoute[];
  trafficStats?: RouteTrafficStats[];
  onDateRangeChange?: (startDate: string, endDate: string) => void;
}

export default function TrafficView({
  server,
  containers,
  proxyRoutes = [],
  passthroughRoutes = [],
  trafficStats = [],
  onDateRangeChange,
}: TrafficViewProps) {
  const [selectedContainer, setSelectedContainer] = useState<string>('');
  const [activeTab, setActiveTab] = useState(0);
  const [startDate, setStartDate] = useState(() => {
    const d = new Date();
    d.setHours(d.getHours() - 1);
    return d.toISOString().slice(0, 16);
  });
  const [endDate, setEndDate] = useState(() => new Date().toISOString().slice(0, 16));

  const { connections, summary, isLoading, error, autoRefresh, refresh, toggleAutoRefresh, eventStatus } =
    useTraffic(server, selectedContainer || null);

  // Get only running containers
  const runningContainers = containers.filter((c) => c.state === 'Running');

  // Combine routes with traffic data for the overview
  const allRoutesWithTraffic = [
    ...proxyRoutes.map(r => ({
      type: 'proxy' as const,
      route: r,
      traffic: trafficStats.find(t => t.routeId === r.fullDomain) || null,
    })),
    ...passthroughRoutes.map(r => ({
      type: 'passthrough' as const,
      route: r,
      traffic: trafficStats.find(t => t.routeId === `${r.externalPort}-${r.protocol}`) || null,
    })),
  ].sort((a, b) => {
    if (a.route.active !== b.route.active) return a.route.active ? -1 : 1;
    return (b.traffic?.requestsPerMin || 0) - (a.traffic?.requestsPerMin || 0);
  });

  const maxTraffic = Math.max(...allRoutesWithTraffic.map(r => r.traffic?.requestsPerMin || 0), 1);
  const totalRequests = allRoutesWithTraffic.reduce((sum, r) => sum + (r.traffic?.requestsPerMin || 0), 0);

  const handleDateChange = (start: string, end: string) => {
    setStartDate(start);
    setEndDate(end);
    onDateRangeChange?.(start, end);
  };

  return (
    <Box sx={{ p: 2 }}>
      {/* Header */}
      <Typography variant="h5" sx={{ mb: 2 }}>Traffic Monitor</Typography>

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
        <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)}>
          <Tab label="Route Traffic" />
          <Tab label="Container Connections" />
        </Tabs>
      </Box>

      {/* Route Traffic Tab */}
      {activeTab === 0 && (
        <>
          {/* Date Range Selector */}
          <Card variant="outlined" sx={{ mb: 2 }}>
            <CardContent>
              <Stack direction="row" spacing={2} alignItems="center">
                <Typography variant="body2" color="text.secondary">Time Range:</Typography>
                <TextField
                  type="datetime-local"
                  size="small"
                  label="Start"
                  value={startDate}
                  onChange={(e) => handleDateChange(e.target.value, endDate)}
                  InputLabelProps={{ shrink: true }}
                  sx={{ width: 220 }}
                />
                <TextField
                  type="datetime-local"
                  size="small"
                  label="End"
                  value={endDate}
                  onChange={(e) => handleDateChange(startDate, e.target.value)}
                  InputLabelProps={{ shrink: true }}
                  sx={{ width: 220 }}
                />
                <Tooltip title="Refresh">
                  <IconButton onClick={() => onDateRangeChange?.(startDate, endDate)} size="small">
                    <RefreshIcon />
                  </IconButton>
                </Tooltip>
              </Stack>
            </CardContent>
          </Card>

          {/* Summary */}
          <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
            <Stack direction="row" spacing={4} divider={<Divider orientation="vertical" flexItem />}>
              <Box>
                <Typography variant="caption" color="text.secondary">Total Routes</Typography>
                <Typography variant="h5">{allRoutesWithTraffic.length}</Typography>
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">Active</Typography>
                <Typography variant="h5">{allRoutesWithTraffic.filter(r => r.route.active).length}</Typography>
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">Total Requests/min</Typography>
                <Typography variant="h5">{formatTraffic(totalRequests)}</Typography>
              </Box>
            </Stack>
          </Paper>

          {/* Route Traffic List */}
          {allRoutesWithTraffic.length > 0 ? (
            <Stack spacing={1}>
              {allRoutesWithTraffic.map(({ type, route, traffic }) => {
                const isProxy = type === 'proxy';
                const proxyRoute = isProxy ? (route as ProxyRoute) : null;
                const passthroughRoute = !isProxy ? (route as PassthroughRoute) : null;
                const requests = traffic?.requestsPerMin || 0;
                const percentage = maxTraffic > 0 ? (requests / maxTraffic) * 100 : 0;
                const routeKey = isProxy
                  ? proxyRoute?.fullDomain
                  : `${passthroughRoute?.externalPort}-${passthroughRoute?.protocol}`;

                return (
                  <Paper
                    key={routeKey}
                    sx={{
                      p: 1.5,
                      opacity: route.active ? 1 : 0.5,
                      bgcolor: route.active ? 'background.paper' : 'grey.100',
                    }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                      {isProxy ? (
                        <PublicIcon sx={{ fontSize: 16, color: 'primary.main' }} />
                      ) : (
                        <CableIcon sx={{ fontSize: 16, color: 'secondary.main' }} />
                      )}
                      <Typography
                        variant="body2"
                        sx={{
                          flex: 1,
                          fontFamily: 'monospace',
                          fontSize: '0.8rem',
                          fontWeight: 500,
                          textDecoration: route.active ? 'none' : 'line-through',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {isProxy ? proxyRoute?.fullDomain : `:${passthroughRoute?.externalPort}`}
                      </Typography>
                      <Chip
                        label={isProxy
                          ? (isGRPCRoute(proxyRoute?.protocol) ? 'gRPC' : 'HTTP')
                          : getRouteProtocolName(passthroughRoute?.protocol)
                        }
                        size="small"
                        color={isProxy ? 'primary' : 'secondary'}
                        variant="outlined"
                        sx={{ height: 18, fontSize: '0.65rem' }}
                      />
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ minWidth: 80, textAlign: 'right' }}
                      >
                        {requests > 0 ? `${formatTraffic(requests)} req/min` : 'No traffic'}
                      </Typography>
                    </Box>
                    <LinearProgress
                      variant="determinate"
                      value={percentage}
                      sx={{
                        height: 6,
                        borderRadius: 1,
                        bgcolor: 'grey.200',
                        '& .MuiLinearProgress-bar': {
                          bgcolor: route.active
                            ? (isProxy ? 'primary.main' : 'secondary.main')
                            : 'grey.400',
                          borderRadius: 1,
                        },
                      }}
                    />
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 0.5 }}>
                      <Typography variant="caption" color="text.secondary">
                        → {isProxy
                          ? `${proxyRoute?.containerIp}:${proxyRoute?.port}`
                          : `${passthroughRoute?.targetIp}:${passthroughRoute?.targetPort}`
                        }
                        {(isProxy ? proxyRoute?.appName : passthroughRoute?.containerName) && (
                          <span> ({isProxy ? proxyRoute?.appName : passthroughRoute?.containerName})</span>
                        )}
                      </Typography>
                      {traffic && traffic.bytesPerMin > 0 && (
                        <Typography variant="caption" color="text.secondary">
                          {formatBytes(traffic.bytesPerMin)}/min
                        </Typography>
                      )}
                    </Box>
                  </Paper>
                );
              })}
            </Stack>
          ) : (
            <Alert severity="info">No routes configured. Add routes in the Network tab to see traffic data.</Alert>
          )}
        </>
      )}

      {/* Container Connections Tab */}
      {activeTab === 1 && (
        <>
          {/* Container selector */}
          <Card variant="outlined" sx={{ mb: 2 }}>
            <CardContent>
              <Stack direction="row" spacing={2} alignItems="center" justifyContent="space-between">
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
        </>
      )}
    </Box>
  );
}
