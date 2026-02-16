'use client';

import { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  CircularProgress,
  Button,
  Switch,
  FormControlLabel,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Link,
  Autocomplete,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import PublicIcon from '@mui/icons-material/Public';
import CableIcon from '@mui/icons-material/Cable';
import { NetworkTopology, ProxyRoute, DNSRecord, RouteProtocol, PassthroughRoute, getRouteProtocolName, isGRPCRoute } from '@/src/types/app';

interface NetworkTopologyViewProps {
  topology: NetworkTopology;
  routes: ProxyRoute[];
  passthroughRoutes?: PassthroughRoute[];
  dnsRecords?: DNSRecord[];
  baseDomain?: string;
  isLoading: boolean;
  error?: Error | null;
  includeStopped: boolean;
  onIncludeStoppedChange: (value: boolean) => void;
  onAddRoute?: (domain: string, targetIp: string, targetPort: number, protocol?: RouteProtocol) => Promise<void>;
  onDeleteRoute?: (domain: string) => Promise<void>;
  onToggleRoute?: (domain: string, enabled: boolean) => Promise<void>;
  onAddPassthroughRoute?: (externalPort: number, targetIp: string, targetPort: number, protocol?: RouteProtocol, containerName?: string) => Promise<void>;
  onDeletePassthroughRoute?: (externalPort: number, protocol?: RouteProtocol) => Promise<void>;
  onTogglePassthroughRoute?: (externalPort: number, protocol: RouteProtocol, enabled: boolean) => Promise<void>;
  onRefresh: () => void;
}

// Unified Route Table Component - shows both proxy and passthrough routes
interface UnifiedRouteTableProps {
  proxyRoutes: ProxyRoute[];
  passthroughRoutes: PassthroughRoute[];
  onDeleteProxyRoute?: (domain: string) => void;
  onToggleProxyRoute?: (domain: string, enabled: boolean) => void;
  onDeletePassthroughRoute?: (externalPort: number, protocol?: RouteProtocol) => void;
  onTogglePassthroughRoute?: (externalPort: number, protocol: RouteProtocol, enabled: boolean) => void;
}

function UnifiedRouteTable({
  proxyRoutes,
  passthroughRoutes,
  onDeleteProxyRoute,
  onToggleProxyRoute,
  onDeletePassthroughRoute,
  onTogglePassthroughRoute
}: UnifiedRouteTableProps) {
  const totalRoutes = proxyRoutes.length + passthroughRoutes.length;

  if (totalRoutes === 0) {
    return (
      <Box sx={{ textAlign: 'center', py: 4 }}>
        <Typography color="text.secondary">No routes configured</Typography>
      </Box>
    );
  }

  return (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Type</TableCell>
            <TableCell>Endpoint</TableCell>
            <TableCell>Target</TableCell>
            <TableCell>Protocol</TableCell>
            <TableCell>Container</TableCell>
            <TableCell>Enabled</TableCell>
            <TableCell align="right">Actions</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {/* Proxy Routes */}
          {proxyRoutes.map((route) => (
            <TableRow key={`proxy-${route.fullDomain || route.subdomain}`} sx={{ opacity: route.active ? 1 : 0.6 }}>
              <TableCell>
                <Tooltip title="Proxy: TLS terminated at Caddy">
                  <Chip
                    icon={<PublicIcon sx={{ fontSize: 16 }} />}
                    label="Proxy"
                    size="small"
                    color="primary"
                    variant="outlined"
                  />
                </Tooltip>
              </TableCell>
              <TableCell>
                <Link
                  href={`https://${route.fullDomain}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 0.5,
                    textDecoration: route.active ? 'none' : 'line-through',
                    color: route.active ? 'primary.main' : 'text.disabled',
                  }}
                >
                  {route.fullDomain}
                  <OpenInNewIcon sx={{ fontSize: 14 }} />
                </Link>
              </TableCell>
              <TableCell>
                <Typography variant="body2" fontFamily="monospace">
                  {route.containerIp ? `${route.containerIp}:${route.port}` : 'N/A'}
                </Typography>
              </TableCell>
              <TableCell>
                <Chip
                  label={getRouteProtocolName(route.protocol)}
                  color={isGRPCRoute(route.protocol) ? 'info' : 'default'}
                  size="small"
                  variant="outlined"
                />
              </TableCell>
              <TableCell>
                <Typography variant="body2" color="text.secondary">
                  {route.appName || '-'}
                </Typography>
              </TableCell>
              <TableCell>
                <Switch
                  size="small"
                  checked={route.active}
                  onChange={(e) => onToggleProxyRoute?.(route.fullDomain, e.target.checked)}
                  disabled={!onToggleProxyRoute}
                />
              </TableCell>
              <TableCell align="right">
                {onDeleteProxyRoute && (
                  <Tooltip title="Delete route">
                    <IconButton
                      size="small"
                      color="error"
                      onClick={() => onDeleteProxyRoute(route.fullDomain)}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                )}
              </TableCell>
            </TableRow>
          ))}
          {/* Passthrough Routes */}
          {passthroughRoutes.map((route) => (
            <TableRow key={`passthrough-${route.externalPort}-${route.protocol}`} sx={{ opacity: route.active ? 1 : 0.6 }}>
              <TableCell>
                <Tooltip title="Passthrough: Direct TCP/UDP forwarding (mTLS supported)">
                  <Chip
                    icon={<CableIcon sx={{ fontSize: 16 }} />}
                    label="Passthrough"
                    size="small"
                    color="secondary"
                    variant="outlined"
                  />
                </Tooltip>
              </TableCell>
              <TableCell>
                <Typography
                  variant="body2"
                  fontFamily="monospace"
                  sx={{ textDecoration: route.active ? 'none' : 'line-through' }}
                >
                  :{route.externalPort}
                </Typography>
              </TableCell>
              <TableCell>
                <Typography variant="body2" fontFamily="monospace">
                  {route.targetIp}:{route.targetPort}
                </Typography>
              </TableCell>
              <TableCell>
                <Chip
                  label={getRouteProtocolName(route.protocol)}
                  color="warning"
                  size="small"
                  variant="outlined"
                />
              </TableCell>
              <TableCell>
                <Typography variant="body2" color="text.secondary">
                  {route.containerName || '-'}
                </Typography>
              </TableCell>
              <TableCell>
                <Switch
                  size="small"
                  checked={route.active}
                  onChange={(e) => onTogglePassthroughRoute?.(route.externalPort, route.protocol, e.target.checked)}
                  disabled={!onTogglePassthroughRoute}
                />
              </TableCell>
              <TableCell align="right">
                {onDeletePassthroughRoute && (
                  <Tooltip title="Delete route">
                    <IconButton
                      size="small"
                      color="error"
                      onClick={() => onDeletePassthroughRoute(route.externalPort, route.protocol)}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

export default function NetworkTopologyView({
  topology,
  routes,
  passthroughRoutes = [],
  dnsRecords = [],
  baseDomain = '',
  isLoading,
  error,
  includeStopped,
  onIncludeStoppedChange,
  onAddRoute,
  onDeleteRoute,
  onToggleRoute,
  onAddPassthroughRoute,
  onDeletePassthroughRoute,
  onTogglePassthroughRoute,
  onRefresh,
}: NetworkTopologyViewProps) {
  // Dialog states
  const [addRouteDialog, setAddRouteDialog] = useState(false);
  const [routeType, setRouteType] = useState<'proxy' | 'passthrough'>('proxy');
  const [newRoute, setNewRoute] = useState({
    domain: '',
    targetIp: '',
    targetPort: '',
    protocol: 'ROUTE_PROTOCOL_HTTP' as RouteProtocol,
    externalPort: '',
  });
  const [deleteRouteDialog, setDeleteRouteDialog] = useState<{ open: boolean; domain: string }>({
    open: false,
    domain: '',
  });
  const [deletePassthroughDialog, setDeletePassthroughDialog] = useState<{ open: boolean; externalPort: number; protocol: RouteProtocol }>({
    open: false,
    externalPort: 0,
    protocol: 'ROUTE_PROTOCOL_TCP',
  });

  // Build domain suggestions from DNS records
  // Each record has: name (subdomain like "pes"), data (full domain like "pes.kafeido.app")
  const domainSuggestions = dnsRecords.map(r => ({
    subdomain: r.name,
    fullDomain: r.data,
  }));

  // Also add existing route domains if not already in suggestions
  const existingDomains = routes.map(r => r.fullDomain).filter(Boolean);
  existingDomains.forEach(domain => {
    if (!domainSuggestions.find(s => s.fullDomain === domain)) {
      const subdomain = domain.replace('.' + baseDomain, '');
      domainSuggestions.push({ subdomain, fullDomain: domain });
    }
  });

  // Extract container options from topology nodes
  const containerOptions = topology.nodes
    .filter(node => node.type === 'container' && node.ipAddress && node.state === 'running')
    .map(node => ({
      name: node.name,
      ip: node.ipAddress || '',
    }));

  const handleAddRoute = async () => {
    if (routeType === 'proxy') {
      if (onAddRoute && newRoute.domain && newRoute.targetIp && newRoute.targetPort) {
        await onAddRoute(newRoute.domain, newRoute.targetIp, parseInt(newRoute.targetPort, 10), newRoute.protocol);
        setAddRouteDialog(false);
        setNewRoute({ domain: '', targetIp: '', targetPort: '', protocol: 'ROUTE_PROTOCOL_HTTP', externalPort: '' });
        setRouteType('proxy');
      }
    } else {
      if (onAddPassthroughRoute && newRoute.externalPort && newRoute.targetIp && newRoute.targetPort) {
        const containerName = containerOptions.find(c => c.ip === newRoute.targetIp)?.name;
        await onAddPassthroughRoute(
          parseInt(newRoute.externalPort, 10),
          newRoute.targetIp,
          parseInt(newRoute.targetPort, 10),
          newRoute.protocol,
          containerName
        );
        setAddRouteDialog(false);
        setNewRoute({ domain: '', targetIp: '', targetPort: '', protocol: 'ROUTE_PROTOCOL_TCP', externalPort: '' });
        setRouteType('proxy');
      }
    }
  };

  const handleDeleteRoute = (domain: string) => {
    setDeleteRouteDialog({ open: true, domain });
  };

  const handleDeletePassthroughRoute = (externalPort: number, protocol?: RouteProtocol) => {
    setDeletePassthroughDialog({ open: true, externalPort, protocol: protocol || 'ROUTE_PROTOCOL_TCP' });
  };

  const handleConfirmDeletePassthroughRoute = async () => {
    if (onDeletePassthroughRoute) {
      await onDeletePassthroughRoute(deletePassthroughDialog.externalPort, deletePassthroughDialog.protocol);
      setDeletePassthroughDialog({ open: false, externalPort: 0, protocol: 'ROUTE_PROTOCOL_TCP' });
    }
  };

  const handleConfirmDeleteRoute = async () => {
    if (onDeleteRoute) {
      await onDeleteRoute(deleteRouteDialog.domain);
      setDeleteRouteDialog({ open: false, domain: '' });
    }
  };

  if (isLoading && topology.nodes.length === 0) {
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
          Failed to load network topology
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
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5">Network Topology</Typography>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <FormControlLabel
            control={
              <Switch
                checked={includeStopped}
                onChange={(e) => onIncludeStoppedChange(e.target.checked)}
              />
            }
            label="Include stopped"
          />
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={onRefresh}
            disabled={isLoading}
          >
            Refresh
          </Button>
        </Box>
      </Box>

      {/* Route Table */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h6">
          Routes ({routes.length + passthroughRoutes.length})
        </Typography>
        {(onAddRoute || onAddPassthroughRoute) && (
          <Button
            variant="outlined"
            startIcon={<AddIcon />}
            onClick={() => setAddRouteDialog(true)}
          >
            Add Route
          </Button>
        )}
      </Box>
      <Paper>
        <UnifiedRouteTable
          proxyRoutes={routes}
          passthroughRoutes={passthroughRoutes}
          onDeleteProxyRoute={onDeleteRoute ? handleDeleteRoute : undefined}
          onToggleProxyRoute={onToggleRoute}
          onDeletePassthroughRoute={onDeletePassthroughRoute ? handleDeletePassthroughRoute : undefined}
          onTogglePassthroughRoute={onTogglePassthroughRoute}
        />
      </Paper>

      {/* Add Route Dialog */}
      <Dialog open={addRouteDialog} onClose={() => setAddRouteDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Add Route</DialogTitle>
        <DialogContent>
          {/* Route Type Selection */}
          <FormControl fullWidth sx={{ mb: 2, mt: 1 }}>
            <InputLabel id="route-type-label">Route Type</InputLabel>
            <Select
              labelId="route-type-label"
              value={routeType}
              label="Route Type"
              onChange={(e) => {
                const newType = e.target.value as 'proxy' | 'passthrough';
                setRouteType(newType);
                // Reset protocol based on type
                if (newType === 'proxy') {
                  setNewRoute({ ...newRoute, protocol: 'ROUTE_PROTOCOL_HTTP', externalPort: '' });
                } else {
                  setNewRoute({ ...newRoute, protocol: 'ROUTE_PROTOCOL_TCP', domain: '' });
                }
              }}
            >
              <MenuItem value="proxy">
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <PublicIcon fontSize="small" />
                  Proxy (HTTP/gRPC) - TLS terminated at Caddy
                </Box>
              </MenuItem>
              <MenuItem value="passthrough">
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <CableIcon fontSize="small" />
                  Passthrough (TCP/UDP) - Direct forwarding, mTLS supported
                </Box>
              </MenuItem>
            </Select>
          </FormControl>

          {routeType === 'proxy' ? (
            <>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Create a proxy route to map a domain to a container. TLS is terminated at Caddy.
              </Typography>

              {/* Domain - Autocomplete with suggestions from DNS records */}
              <Autocomplete
                freeSolo
                options={domainSuggestions}
                getOptionLabel={(option) => {
                  if (typeof option === 'string') return option;
                  return option.fullDomain;
                }}
                value={newRoute.domain}
                onChange={(_, value) => {
                  if (typeof value === 'string') {
                    setNewRoute({ ...newRoute, domain: value });
                  } else if (value) {
                    setNewRoute({ ...newRoute, domain: value.fullDomain });
                  }
                }}
                onInputChange={(_, value) => setNewRoute({ ...newRoute, domain: value })}
                renderOption={(props, option) => (
                  <li {...props} key={typeof option === 'string' ? option : option.fullDomain}>
                    <Box>
                      <Typography variant="body2" fontWeight={500}>
                        {typeof option === 'string' ? option : option.subdomain}
                      </Typography>
                      {typeof option !== 'string' && (
                        <Typography variant="caption" color="text.secondary">
                          {option.fullDomain}
                        </Typography>
                      )}
                    </Box>
                  </li>
                )}
                renderInput={(params) => (
                  <TextField
                    {...params}
                    fullWidth
                    label="Domain"
                    placeholder={baseDomain ? `subdomain.${baseDomain}` : 'test.example.com'}
                    helperText={baseDomain ? `Base domain: ${baseDomain}` : 'Enter the full domain name'}
                    sx={{ mb: 2 }}
                  />
                )}
              />

              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel id="protocol-select-label">Protocol</InputLabel>
                <Select
                  labelId="protocol-select-label"
                  value={newRoute.protocol}
                  label="Protocol"
                  onChange={(e) => setNewRoute({ ...newRoute, protocol: e.target.value as RouteProtocol })}
                >
                  <MenuItem value="ROUTE_PROTOCOL_HTTP">HTTP (Web traffic)</MenuItem>
                  <MenuItem value="ROUTE_PROTOCOL_GRPC">gRPC (HTTP/2)</MenuItem>
                </Select>
              </FormControl>
            </>
          ) : (
            <>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Create a passthrough route for direct TCP/UDP port forwarding. Ideal for mTLS or custom protocols.
              </Typography>

              <TextField
                fullWidth
                label="External Port"
                placeholder="50051"
                type="number"
                value={newRoute.externalPort}
                onChange={(e) => setNewRoute({ ...newRoute, externalPort: e.target.value })}
                helperText="The port exposed on the host"
                sx={{ mb: 2 }}
              />

              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel id="passthrough-protocol-label">Protocol</InputLabel>
                <Select
                  labelId="passthrough-protocol-label"
                  value={newRoute.protocol}
                  label="Protocol"
                  onChange={(e) => setNewRoute({ ...newRoute, protocol: e.target.value as RouteProtocol })}
                >
                  <MenuItem value="ROUTE_PROTOCOL_TCP">TCP</MenuItem>
                  <MenuItem value="ROUTE_PROTOCOL_UDP">UDP</MenuItem>
                </Select>
              </FormControl>
            </>
          )}

          {/* Target - Select from containers or custom input (common for both types) */}
          <Autocomplete
            freeSolo
            options={containerOptions}
            getOptionLabel={(option) => {
              if (typeof option === 'string') return option;
              return `${option.name} (${option.ip})`;
            }}
            value={newRoute.targetIp}
            onChange={(_, value) => {
              if (typeof value === 'string') {
                setNewRoute({ ...newRoute, targetIp: value });
              } else if (value) {
                setNewRoute({ ...newRoute, targetIp: value.ip });
              }
            }}
            onInputChange={(_, value) => {
              // Only update if it looks like an IP or the field is being cleared
              if (!value || value.match(/^[\d.]+$/) || value.includes('(')) {
                const ipMatch = value.match(/\(([^)]+)\)/);
                if (ipMatch) {
                  setNewRoute({ ...newRoute, targetIp: ipMatch[1] });
                } else {
                  setNewRoute({ ...newRoute, targetIp: value });
                }
              }
            }}
            renderOption={(props, option) => (
              <li {...props} key={typeof option === 'string' ? option : option.ip}>
                <Box>
                  <Typography variant="body2" fontWeight={500}>
                    {typeof option === 'string' ? option : option.name}
                  </Typography>
                  {typeof option !== 'string' && (
                    <Typography variant="caption" color="text.secondary">
                      {option.ip}
                    </Typography>
                  )}
                </Box>
              </li>
            )}
            renderInput={(params) => (
              <TextField
                {...params}
                fullWidth
                label="Target IP"
                placeholder="10.0.3.136"
                helperText="Select a container or enter IP manually"
                sx={{ mb: 2 }}
              />
            )}
          />

          <TextField
            fullWidth
            label="Target Port"
            placeholder={routeType === 'proxy' ? '8080' : '50051'}
            type="number"
            value={newRoute.targetPort}
            onChange={(e) => setNewRoute({ ...newRoute, targetPort: e.target.value })}
            helperText="The port on the container"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAddRouteDialog(false)}>Cancel</Button>
          <Button
            onClick={handleAddRoute}
            variant="contained"
            disabled={
              routeType === 'proxy'
                ? !newRoute.domain || !newRoute.targetIp || !newRoute.targetPort
                : !newRoute.externalPort || !newRoute.targetIp || !newRoute.targetPort
            }
          >
            Add Route
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Route Confirmation Dialog */}
      <Dialog open={deleteRouteDialog.open} onClose={() => setDeleteRouteDialog({ open: false, domain: '' })}>
        <DialogTitle>Delete Proxy Route</DialogTitle>
        <DialogContent>
          <Typography gutterBottom>
            Are you sure you want to delete the route for <strong>{deleteRouteDialog.domain}</strong>?
          </Typography>
          <Typography variant="body2" color="text.secondary">
            This will remove the proxy configuration for this domain.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteRouteDialog({ open: false, domain: '' })}>
            Cancel
          </Button>
          <Button onClick={handleConfirmDeleteRoute} color="error">
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Passthrough Route Confirmation Dialog */}
      <Dialog open={deletePassthroughDialog.open} onClose={() => setDeletePassthroughDialog({ open: false, externalPort: 0, protocol: 'ROUTE_PROTOCOL_TCP' })}>
        <DialogTitle>Delete Passthrough Route</DialogTitle>
        <DialogContent>
          <Typography gutterBottom>
            Are you sure you want to delete the passthrough route for port <strong>{deletePassthroughDialog.externalPort}</strong>?
          </Typography>
          <Typography variant="body2" color="text.secondary">
            This will remove the TCP/UDP port forwarding rule from iptables.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeletePassthroughDialog({ open: false, externalPort: 0, protocol: 'ROUTE_PROTOCOL_TCP' })}>
            Cancel
          </Button>
          <Button onClick={handleConfirmDeletePassthroughRoute} color="error">
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
