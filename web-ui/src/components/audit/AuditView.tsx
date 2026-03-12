'use client';

import { useState, useCallback } from 'react';
import {
  Box,
  Typography,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  TextField,
  Stack,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  CircularProgress,
  Alert,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import { Server } from '@/src/types/server';
import { AuditLogsParams } from '@/src/types/audit';
import { useAudit } from '@/src/lib/hooks/useAudit';

interface AuditViewProps {
  server: Server;
}

function formatDate(iso: string): string {
  if (!iso) return '-';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

const ACTION_OPTIONS = [
  { value: '', label: 'All' },
  { value: 'ssh_login', label: 'SSH Login' },
  { value: 'terminal_access', label: 'Terminal Access' },
  { value: 'api_post', label: 'API POST' },
  { value: 'api_put', label: 'API PUT' },
  { value: 'api_delete', label: 'API DELETE' },
  { value: 'api_get', label: 'API GET' },
  { value: 'EVENT_TYPE_CONTAINER_CREATED', label: 'Container Created' },
  { value: 'EVENT_TYPE_CONTAINER_STARTED', label: 'Container Started' },
  { value: 'EVENT_TYPE_CONTAINER_STOPPED', label: 'Container Stopped' },
  { value: 'EVENT_TYPE_CONTAINER_DELETED', label: 'Container Deleted' },
  { value: 'EVENT_TYPE_APP_DEPLOYED', label: 'App Deployed' },
  { value: 'EVENT_TYPE_APP_STOPPED', label: 'App Stopped' },
  { value: 'EVENT_TYPE_ROUTE_ADDED', label: 'Route Added' },
  { value: 'EVENT_TYPE_ROUTE_REMOVED', label: 'Route Removed' },
];

const RESOURCE_TYPE_OPTIONS = [
  { value: '', label: 'All' },
  { value: 'container', label: 'Container' },
  { value: 'app', label: 'App' },
  { value: 'route', label: 'Route' },
  { value: 'api', label: 'API' },
];

// Method-specific colors for API actions
const METHOD_STYLES: Record<string, { label: string; bg: string; color: string }> = {
  api_get:    { label: 'GET',    bg: '#e8f5e9', color: '#2e7d32' },
  api_post:   { label: 'POST',   bg: '#e3f2fd', color: '#1565c0' },
  api_put:    { label: 'PUT',    bg: '#fff3e0', color: '#e65100' },
  api_delete: { label: 'DELETE', bg: '#ffebee', color: '#c62828' },
  api_patch:  { label: 'PATCH',  bg: '#f3e5f5', color: '#7b1fa2' },
};

function ActionChip({ action }: { action: string }) {
  // SSH login
  if (action === 'ssh_login') {
    return <Chip label="SSH Login" color="info" size="small" />;
  }

  // Terminal access
  if (action === 'terminal_access') {
    return <Chip label="Terminal" color="secondary" size="small" />;
  }

  // HTTP method-specific chips
  const methodStyle = METHOD_STYLES[action];
  if (methodStyle) {
    return (
      <Chip
        label={methodStyle.label}
        size="small"
        sx={{
          bgcolor: methodStyle.bg,
          color: methodStyle.color,
          fontWeight: 'bold',
          border: `1px solid ${methodStyle.color}40`,
        }}
      />
    );
  }

  // Legacy api_request (before the method split) — try to infer method from resourceId
  if (action === 'api_request') {
    return <Chip label="API" size="small" variant="outlined" />;
  }

  // Also handle if action is still the generic form but with method embedded
  if (action.startsWith('api_')) {
    const method = action.replace('api_', '').toUpperCase();
    return (
      <Chip
        label={method}
        size="small"
        sx={{ bgcolor: '#f5f5f5', color: '#616161', fontWeight: 'bold', border: '1px solid #bdbdbd' }}
      />
    );
  }

  // Event bus events
  if (action.startsWith('EVENT_TYPE_')) {
    const label = action
      .replace('EVENT_TYPE_', '')
      .split('_')
      .map(w => w.charAt(0) + w.slice(1).toLowerCase())
      .join(' ');
    return <Chip label={label} color="success" size="small" variant="outlined" />;
  }

  return <Chip label={action} size="small" variant="outlined" />;
}

export default function AuditView({ server }: AuditViewProps) {
  // Filter state
  const [username, setUsername] = useState('');
  const [action, setAction] = useState('');
  const [resourceType, setResourceType] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  const params: AuditLogsParams = {
    ...(username && { username }),
    ...(action && { action }),
    ...(resourceType && { resource_type: resourceType }),
    ...(fromDate && { from: new Date(fromDate).toISOString() }),
    ...(toDate && { to: new Date(toDate).toISOString() }),
    limit: rowsPerPage,
    offset: page * rowsPerPage,
  };

  const { logs, totalCount, isLoading, error, refresh } = useAudit(server, params);

  const handleChangePage = useCallback((_: unknown, newPage: number) => {
    setPage(newPage);
  }, []);

  const handleChangeRowsPerPage = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  }, []);

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>
          Audit Logs
        </Typography>
        <IconButton onClick={refresh} disabled={isLoading}>
          <RefreshIcon />
        </IconButton>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          Failed to load audit logs: {(error as Error).message}
        </Alert>
      )}

      {/* Filters */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
          <TextField
            label="Username"
            size="small"
            value={username}
            onChange={e => { setUsername(e.target.value); setPage(0); }}
            sx={{ minWidth: 140 }}
          />
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel>Action</InputLabel>
            <Select
              value={action}
              label="Action"
              onChange={e => { setAction(e.target.value); setPage(0); }}
            >
              {ACTION_OPTIONS.map(opt => (
                <MenuItem key={opt.value} value={opt.value}>{opt.label}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Resource Type</InputLabel>
            <Select
              value={resourceType}
              label="Resource Type"
              onChange={e => { setResourceType(e.target.value); setPage(0); }}
            >
              {RESOURCE_TYPE_OPTIONS.map(opt => (
                <MenuItem key={opt.value} value={opt.value}>{opt.label}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <TextField
            label="From"
            type="datetime-local"
            size="small"
            value={fromDate}
            onChange={e => { setFromDate(e.target.value); setPage(0); }}
            slotProps={{ inputLabel: { shrink: true } }}
            sx={{ minWidth: 200 }}
          />
          <TextField
            label="To"
            type="datetime-local"
            size="small"
            value={toDate}
            onChange={e => { setToDate(e.target.value); setPage(0); }}
            slotProps={{ inputLabel: { shrink: true } }}
            sx={{ minWidth: 200 }}
          />
        </Stack>
      </Paper>

      {/* Table */}
      <TableContainer component={Paper}>
        {isLoading && (
          <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
            <CircularProgress size={24} />
          </Box>
        )}
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Timestamp</TableCell>
              <TableCell>Username</TableCell>
              <TableCell>Action</TableCell>
              <TableCell>Resource</TableCell>
              <TableCell>Detail</TableCell>
              <TableCell>Source IP</TableCell>
              <TableCell>Status</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {logs.length === 0 && !isLoading ? (
              <TableRow>
                <TableCell colSpan={7} align="center">
                  <Typography variant="body2" color="text.secondary" sx={{ py: 3 }}>
                    No audit log entries found
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              logs.map(entry => (
                <TableRow key={entry.id} hover>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>
                    {formatDate(entry.timestamp)}
                  </TableCell>
                  <TableCell>{entry.username || '-'}</TableCell>
                  <TableCell>
                    <ActionChip action={entry.action} />
                  </TableCell>
                  <TableCell>
                    {entry.resourceType === 'api' ? (
                      // For API entries, resourceId is "PUT /v1/..." — show just the path
                      <Typography variant="body2" component="span" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                        {entry.resourceId.replace(/^(GET|POST|PUT|DELETE|PATCH)\s+/, '') || '-'}
                      </Typography>
                    ) : (
                      <>
                        {entry.resourceType && (
                          <Typography variant="body2" component="span" color="text.secondary">
                            {entry.resourceType}/
                          </Typography>
                        )}
                        {entry.resourceId || '-'}
                      </>
                    )}
                  </TableCell>
                  <TableCell sx={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {entry.detail || '-'}
                  </TableCell>
                  <TableCell>{entry.sourceIp || '-'}</TableCell>
                  <TableCell>
                    {entry.statusCode > 0 ? entry.statusCode : '-'}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        <TablePagination
          component="div"
          count={totalCount}
          page={page}
          onPageChange={handleChangePage}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={handleChangeRowsPerPage}
          rowsPerPageOptions={[25, 50, 100]}
        />
      </TableContainer>
    </Box>
  );
}
