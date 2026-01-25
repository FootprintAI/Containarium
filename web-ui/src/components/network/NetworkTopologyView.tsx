'use client';

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
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import CloudIcon from '@mui/icons-material/Cloud';
import RouterIcon from '@mui/icons-material/Router';
import DnsIcon from '@mui/icons-material/Dns';
import BlockIcon from '@mui/icons-material/Block';
import { NetworkTopology, ProxyRoute, NetworkNode } from '@/src/types/app';

interface NetworkTopologyViewProps {
  topology: NetworkTopology;
  routes: ProxyRoute[];
  isLoading: boolean;
  error?: Error | null;
  includeStopped: boolean;
  onIncludeStoppedChange: (value: boolean) => void;
  onRefresh: () => void;
}

// Simple visualization component for the network
function NetworkDiagram({ topology }: { topology: NetworkTopology }) {
  const proxyNode = topology.nodes.find(n => n.type === 'proxy');
  const containerNodes = topology.nodes.filter(n => n.type === 'container');

  return (
    <Box sx={{ p: 3, textAlign: 'center' }}>
      {/* Internet */}
      <Box sx={{ mb: 2 }}>
        <CloudIcon sx={{ fontSize: 40, color: 'primary.main' }} />
        <Typography variant="body2" color="text.secondary">
          Internet
        </Typography>
      </Box>

      {/* Arrow */}
      <Box sx={{ height: 30, borderLeft: '2px solid', borderColor: 'grey.400', width: 0, mx: 'auto' }} />

      {/* Proxy */}
      {proxyNode && (
        <Paper
          sx={{
            p: 2,
            display: 'inline-block',
            minWidth: 200,
            mb: 2,
            bgcolor: 'primary.light',
            color: 'primary.contrastText',
          }}
        >
          <RouterIcon sx={{ fontSize: 30 }} />
          <Typography variant="subtitle1">{proxyNode.name}</Typography>
          <Typography variant="body2">{proxyNode.ipAddress}</Typography>
          <Chip label="TLS Termination" size="small" sx={{ mt: 1 }} />
        </Paper>
      )}

      {/* Connections */}
      {containerNodes.length > 0 && (
        <>
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'center',
              gap: 2,
              my: 2,
            }}
          >
            {containerNodes.slice(0, 5).map((node, idx) => (
              <Box key={node.id} sx={{ height: 30, borderLeft: '2px solid', borderColor: 'grey.400', width: 0 }} />
            ))}
          </Box>

          {/* Container Nodes */}
          <Box
            sx={{
              display: 'flex',
              flexWrap: 'wrap',
              justifyContent: 'center',
              gap: 2,
            }}
          >
            {containerNodes.map((node) => (
              <ContainerNodeCard key={node.id} node={node} />
            ))}
          </Box>
        </>
      )}

      {/* Network Info */}
      <Box sx={{ mt: 3, p: 2, bgcolor: 'grey.100', borderRadius: 1 }}>
        <Typography variant="body2" color="text.secondary">
          Network: {topology.networkCidr} | Gateway: {topology.gatewayIp}
        </Typography>
      </Box>
    </Box>
  );
}

function ContainerNodeCard({ node }: { node: NetworkNode }) {
  const isRunning = node.state === 'running';

  return (
    <Paper
      sx={{
        p: 2,
        minWidth: 150,
        borderLeft: 4,
        borderColor: isRunning ? 'success.main' : 'grey.400',
        opacity: isRunning ? 1 : 0.7,
      }}
    >
      <DnsIcon sx={{ fontSize: 24, color: isRunning ? 'success.main' : 'grey.500' }} />
      <Typography variant="subtitle2" noWrap sx={{ maxWidth: 130 }}>
        {node.name}
      </Typography>
      <Typography variant="caption" color="text.secondary" display="block">
        {node.ipAddress || 'No IP'}
      </Typography>
      {node.aclName && (
        <Chip
          icon={<BlockIcon sx={{ fontSize: 14 }} />}
          label={node.aclName.replace('acl-', '')}
          size="small"
          variant="outlined"
          sx={{ mt: 0.5, fontSize: 10 }}
        />
      )}
    </Paper>
  );
}

// Route Table Component
function RouteTable({ routes }: { routes: ProxyRoute[] }) {
  if (routes.length === 0) {
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
            <TableCell>Subdomain</TableCell>
            <TableCell>Container IP</TableCell>
            <TableCell>Port</TableCell>
            <TableCell>Status</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {routes.map((route) => (
            <TableRow key={route.subdomain}>
              <TableCell>
                <Typography variant="body2" fontWeight={500}>
                  {route.fullDomain}
                </Typography>
              </TableCell>
              <TableCell>
                <Typography variant="body2" fontFamily="monospace">
                  {route.containerIp}
                </Typography>
              </TableCell>
              <TableCell>
                <Typography variant="body2" fontFamily="monospace">
                  {route.port}
                </Typography>
              </TableCell>
              <TableCell>
                <Chip
                  label={route.active ? 'Active' : 'Inactive'}
                  color={route.active ? 'success' : 'default'}
                  size="small"
                />
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
  isLoading,
  error,
  includeStopped,
  onIncludeStoppedChange,
  onRefresh,
}: NetworkTopologyViewProps) {
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

      {/* Network Diagram */}
      <Paper sx={{ mb: 3 }}>
        <NetworkDiagram topology={topology} />
      </Paper>

      {/* Route Table */}
      <Typography variant="h6" gutterBottom sx={{ mt: 4 }}>
        Route Table
      </Typography>
      <Paper>
        <RouteTable routes={routes} />
      </Paper>
    </Box>
  );
}
